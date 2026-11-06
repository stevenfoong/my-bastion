package main

// PostgreSQL: one client connection: TLS, the bastion token as the password, the real
// connection to the database with credentials from the core, then every
// message relayed, with each statement checked before it goes on (simple
// queries, and Parse in the extended protocol) and audited when it ends.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// SQLSTATE insufficient_privilege, for statements the bastion refuses.
const refusedCode = "42501"

type pending struct {
	stmt Stmt
}

type session struct {
	core     *Core
	id       string
	clientIP string
	client   net.Conn
	be       *pgproto3.Backend
	beMu     sync.Mutex
	fe       *pgproto3.Frontend
	server   net.Conn
	mu       sync.Mutex
	prepared map[string]Stmt // statement name -> its SQL
	portals  map[string]Stmt // portal -> its statement
	queue    []pending       // statements sent, waiting for their result
	txStatus byte
	skipSync bool // an extended-protocol error: drop messages until Sync
	// Audit calls in flight: the session ends (core.Disconnect) only after
	// them, or the core would drop the last statements' rows.
	audits sync.WaitGroup
}

// audit sends a statement's outcome without holding up the relay.
func (s *session) audit(st Stmt, status string, rows int64, tag, errMsg string) {
	s.audits.Add(1)
	go func() {
		defer s.audits.Done()
		s.core.Audit(s.id, st, status, rows, tag, errMsg)
	}()
}

func quote(v string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `'`, `\'`) + "'"
}

func rowsFromTag(tag string) int64 {
	f := strings.Fields(tag)
	if len(f) < 2 {
		return -1
	}
	n, err := strconv.ParseInt(f[len(f)-1], 10, 64)
	if err != nil {
		return -1
	}
	return n
}

func fatal(be *pgproto3.Backend, code, msg string) {
	be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: msg})
	_ = be.Flush()
}

// handle serves one client until either side closes.
func handle(raw net.Conn, core *Core, tlsCfg *tls.Config) {
	defer raw.Close()
	clientIP, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
	conn := raw
	be := pgproto3.NewBackend(conn, conn)
	var startup *pgproto3.StartupMessage
	secure := false
	for startup == nil {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.SSLRequest:
			if _, err := conn.Write([]byte("S")); err != nil {
				return
			}
			tc := tls.Server(raw, tlsCfg)
			if err := tc.Handshake(); err != nil {
				logger.Info("TLS handshake failed", "client", clientIP, "error", err)
				return
			}
			conn, secure = tc, true
			be = pgproto3.NewBackend(conn, conn)
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte("N")); err != nil {
				return
			}
		case *pgproto3.CancelRequest:
			return
		case *pgproto3.StartupMessage:
			startup = m
		default:
			return
		}
	}
	if !secure {
		fatal(be, "28000", "the bastion requires TLS (sslmode=require)")
		return
	}

	// The bastion token is the password.
	be.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := be.Flush(); err != nil {
		return
	}
	if err := be.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return
	}
	msg, err := be.Receive()
	if err != nil {
		return
	}
	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		fatal(be, "28000", "expected a password (your bastion DB token)")
		return
	}
	ctx := context.Background()
	res, err := core.Connect(ctx, strings.TrimSpace(pw.Password), clientIP, "postgres")
	if err != nil {
		code := "28000"
		var ae *apiError
		if errors.As(err, &ae) && ae.Status == 401 {
			code = "28P01"
		}
		logger.Info("connection refused", "client", clientIP, "reason", err)
		fatal(be, code, "bastion: "+err.Error())
		return
	}
	t := res.Target
	dsn := fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=prefer application_name=%s",
		quote(t.Host), t.Port, quote(t.User), quote(t.Database), quote("mybastion "+res.Actor))
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		fatal(be, "08006", "bastion: bad target: "+err.Error())
		core.Disconnect(res.SessionID)
		return
	}
	cfg.Password = t.Password
	pc, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		fatal(be, "08006", "bastion: cannot connect to the database: "+err.Error())
		core.Disconnect(res.SessionID)
		return
	}
	hc, err := pc.Hijack()
	if err != nil {
		fatal(be, "08006", "bastion: "+err.Error())
		core.Disconnect(res.SessionID)
		return
	}
	defer hc.Conn.Close()
	defer core.Disconnect(res.SessionID)

	be.Send(&pgproto3.AuthenticationOk{})
	for k, v := range hc.ParameterStatuses {
		be.Send(&pgproto3.ParameterStatus{Name: k, Value: v})
	}
	be.Send(&pgproto3.BackendKeyData{ProcessID: hc.PID, SecretKey: hc.SecretKey})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: hc.TxStatus})
	if err := be.Flush(); err != nil {
		return
	}
	logger.Info("connected", "client", clientIP, "actor", res.Actor, "session", res.SessionID)

	s := &session{
		core: core, id: res.SessionID, clientIP: clientIP, client: conn, be: be,
		fe: hc.Frontend, server: hc.Conn, prepared: map[string]Stmt{}, portals: map[string]Stmt{},
		txStatus: hc.TxStatus,
	}
	done := make(chan struct{}, 2)
	go func() { s.fromServer(); done <- struct{}{} }()
	go func() { s.fromClient(); done <- struct{}{} }()
	<-done
	conn.Close()
	hc.Conn.Close()
	<-done
	// The deferred core.Disconnect runs after this: let the audits land first.
	s.audits.Wait()
}

func (s *session) toClient(msgs ...pgproto3.BackendMessage) error {
	s.beMu.Lock()
	defer s.beMu.Unlock()
	for _, m := range msgs {
		s.be.Send(m)
	}
	return s.be.Flush()
}

func (s *session) toServer(m pgproto3.FrontendMessage) error {
	s.fe.Send(m)
	return s.fe.Flush()
}

func (s *session) tx() byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txStatus
}

// refuse tells the client a statement was not run.
func (s *session) refuse(msg string, ready bool) error {
	msgs := []pgproto3.BackendMessage{&pgproto3.ErrorResponse{Severity: "ERROR", Code: refusedCode, Message: msg}}
	if ready {
		msgs = append(msgs, &pgproto3.ReadyForQuery{TxStatus: s.tx()})
	}
	return s.toClient(msgs...)
}

// check asks the core about each statement; the first refusal ends it.
func (s *session) check(stmts []Stmt) (string, bool) {
	for _, st := range stmts {
		r, err := s.core.Check(context.Background(), s.id, st)
		if err != nil {
			return "bastion: " + err.Error(), false
		}
		if r.Decision != "allow" {
			return "bastion: " + r.Message, false
		}
	}
	return "", true
}

func (s *session) fromClient() {
	for {
		msg, err := s.be.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			stmts, err := Split(m.String)
			if err != nil {
				s.core.Audit(s.id, Stmt{SQL: m.String, Classes: []string{"other"}}, "refused", -1, "", "unparseable: "+err.Error())
				if s.refuse("bastion: this statement could not be parsed, so it was not run: "+err.Error(), true) != nil {
					return
				}
				continue
			}
			if msg, ok := s.check(stmts); !ok {
				if s.refuse(msg, true) != nil {
					return
				}
				continue
			}
			s.mu.Lock()
			for _, st := range stmts {
				s.queue = append(s.queue, pending{stmt: st})
			}
			s.mu.Unlock()
		case *pgproto3.Parse:
			if s.skipping() {
				continue
			}
			stmts, err := Split(m.Query)
			refusal := ""
			switch {
			case err != nil:
				refusal = "bastion: this statement could not be parsed, so it was not run: " + err.Error()
				s.core.Audit(s.id, Stmt{SQL: m.Query, Classes: []string{"other"}}, "refused", -1, "", "unparseable: "+err.Error())
			case len(stmts) > 1:
				refusal = "bastion: a prepared statement must be a single statement"
			default:
				if msg, ok := s.check(stmts); !ok {
					refusal = msg
				}
			}
			if refusal != "" {
				s.mu.Lock()
				s.skipSync = true
				s.mu.Unlock()
				if s.refuse(refusal, false) != nil {
					return
				}
				continue
			}
			st := Stmt{SQL: m.Query, Classes: []string{"session"}}
			if len(stmts) == 1 {
				st = stmts[0]
			}
			s.mu.Lock()
			s.prepared[m.Name] = st
			s.mu.Unlock()
		case *pgproto3.Bind:
			if s.skipping() {
				continue
			}
			s.mu.Lock()
			s.portals[m.DestinationPortal] = s.prepared[m.PreparedStatement]
			s.mu.Unlock()
		case *pgproto3.Execute:
			if s.skipping() {
				continue
			}
			s.mu.Lock()
			s.queue = append(s.queue, pending{stmt: s.portals[m.Portal]})
			s.mu.Unlock()
		case *pgproto3.Close:
			if s.skipping() {
				continue
			}
			s.mu.Lock()
			if m.ObjectType == 'S' {
				delete(s.prepared, m.Name)
			} else {
				delete(s.portals, m.Name)
			}
			s.mu.Unlock()
		case *pgproto3.Describe, *pgproto3.Flush:
			if s.skipping() {
				continue
			}
		case *pgproto3.Sync:
			s.mu.Lock()
			skipped := s.skipSync
			s.skipSync = false
			s.mu.Unlock()
			if skipped {
				if s.toClient(&pgproto3.ReadyForQuery{TxStatus: s.tx()}) != nil {
					return
				}
				continue
			}
		case *pgproto3.Terminate:
			_ = s.toServer(m)
			return
		}
		if err := s.toServer(msg); err != nil {
			return
		}
	}
}

func (s *session) skipping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.skipSync
}

// pop the statement a result belongs to.
func (s *session) pop() (Stmt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return Stmt{}, false
	}
	p := s.queue[0]
	s.queue = s.queue[1:]
	return p.stmt, true
}

func (s *session) fromServer() {
	for {
		msg, err := s.fe.Receive()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				logger.Debug("server read", "error", err)
			}
			return
		}
		flush := true
		switch m := msg.(type) {
		case *pgproto3.CommandComplete:
			tag := string(m.CommandTag)
			if st, ok := s.pop(); ok {
				s.audit(st, "ok", rowsFromTag(tag), tag, "")
			}
		case *pgproto3.ErrorResponse:
			if st, ok := s.pop(); ok {
				s.audit(st, "error", -1, "", m.Code+" "+m.Message)
			}
		case *pgproto3.ReadyForQuery:
			s.mu.Lock()
			s.txStatus = m.TxStatus
			s.queue = nil // what did not run after an error
			s.mu.Unlock()
		case *pgproto3.DataRow, *pgproto3.CopyData:
			flush = false
		}
		s.beMu.Lock()
		s.be.Send(msg)
		if flush {
			err = s.be.Flush()
		}
		s.beMu.Unlock()
		if err != nil {
			return
		}
	}
}

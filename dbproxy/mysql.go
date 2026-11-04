package main

// MySQL and MariaDB: one client connection. TLS is required, the bastion
// token is the password (asked for in clear inside TLS), the real
// connection to the database is made with credentials from the core, and
// then every command is relayed. The protocol is request/response, so one
// loop reads a command, checks it, forwards it and relays its whole
// response: COM_QUERY and COM_STMT_PREPARE are parsed and checked
// statement by statement, COM_INIT_DB is a USE, and commands the bastion
// cannot inspect (COM_CHANGE_USER, replication, ...) are refused.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	capLongPassword     = 0x1
	capFoundRows        = 0x2
	capLongFlag         = 0x4
	capConnectWithDB    = 0x8
	capNoSchema         = 0x10
	capIgnoreSpace      = 0x100
	capProtocol41       = 0x200
	capInteractive      = 0x400
	capSSL              = 0x800
	capIgnoreSigpipe    = 0x1000
	capTransactions     = 0x2000
	capSecureConn       = 0x8000
	capMultiStatements  = 0x10000
	capMultiResults     = 0x20000
	capPSMultiResults   = 0x40000
	capPluginAuth       = 0x80000
	capConnectAttrs     = 0x100000
	capPluginAuthLenenc = 0x200000
	capDeprecateEOF     = 0x1000000

	// What the bastion offers clients. Not offered: compression, LOAD DATA
	// LOCAL (the client would send a file the bastion does not inspect),
	// query attributes and optional metadata (they change the wire format),
	// session tracking.
	offeredCaps = capLongPassword | capFoundRows | capLongFlag | capConnectWithDB | capNoSchema |
		capIgnoreSpace | capProtocol41 | capInteractive | capSSL | capIgnoreSigpipe |
		capTransactions | capSecureConn | capMultiStatements | capMultiResults |
		capPSMultiResults | capPluginAuth | capConnectAttrs | capPluginAuthLenenc | capDeprecateEOF
	// Flags that change what is on the wire after login: client and server
	// must agree on them for the relay to be transparent.
	wireCaps = capProtocol41 | capDeprecateEOF | capMultiResults | capPSMultiResults

	statusMoreResults = 0x0008
	maxPacket         = 0xffffff

	comQuit            = 0x01
	comInitDB          = 0x02
	comQuery           = 0x03
	comFieldList       = 0x04
	comStatistics      = 0x09
	comPing            = 0x0e
	comStmtPrepare     = 0x16
	comStmtExecute     = 0x17
	comStmtSendLong    = 0x18
	comStmtClose       = 0x19
	comStmtReset       = 0x1a
	comSetOption       = 0x1b
	comResetConnection = 0x1f

	// ER_SPECIFIC_ACCESS_DENIED_ERROR, for statements the bastion refuses.
	errRefused = 1227
	// ER_ACCESS_DENIED_ERROR, for a bad token.
	errAccessDenied = 1045
	errHandshake    = 1043
	// ER_UNKNOWN_ERROR: the database cannot be reached. (Not 2003: codes
	// from 2000 up are the client library's own, and clients misread them.)
	errConnect = 1105

	// The server version clients see; queries go to the real server.
	proxyServerVersion = "8.0.40-mybastion"
	// utf8mb4_general_ci, known to MySQL and MariaDB.
	defaultCollation = 45
)

var mysqlConnID atomic.Uint32

// mconn reads and writes MySQL packets.
type mconn struct {
	c net.Conn
	r *bufio.Reader
	w *bufio.Writer
}

func newMconn(c net.Conn) *mconn {
	return &mconn{c: c, r: bufio.NewReaderSize(c, 64<<10), w: bufio.NewWriterSize(c, 64<<10)}
}

// read one logical packet: its payload (joined across 16 MB pieces), the
// raw bytes as they came, and the sequence id of its first piece.
func (m *mconn) read() (payload, raw []byte, seq byte, err error) {
	first := true
	for {
		var hdr [4]byte
		if _, err = io.ReadFull(m.r, hdr[:]); err != nil {
			return nil, nil, 0, err
		}
		n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		if first {
			seq, first = hdr[3], false
		}
		start := len(raw)
		raw = append(raw, hdr[:]...)
		raw = append(raw, make([]byte, n)...)
		if _, err = io.ReadFull(m.r, raw[start+4:]); err != nil {
			return nil, nil, 0, err
		}
		payload = append(payload, raw[start+4:]...)
		if n < maxPacket {
			return payload, raw, seq, nil
		}
	}
}

// write one logical packet (buffered; flush sends it).
func (m *mconn) write(seq byte, p []byte) error {
	for {
		n := len(p)
		if n > maxPacket {
			n = maxPacket
		}
		hdr := []byte{byte(n), byte(n >> 8), byte(n >> 16), seq}
		if _, err := m.w.Write(hdr); err != nil {
			return err
		}
		if _, err := m.w.Write(p[:n]); err != nil {
			return err
		}
		p, seq = p[n:], seq+1
		if n < maxPacket {
			return nil
		}
	}
}

func (m *mconn) send(seq byte, p []byte) error {
	if err := m.write(seq, p); err != nil {
		return err
	}
	return m.w.Flush()
}

func errPacket(code uint16, state, msg string) []byte {
	p := []byte{0xff, byte(code), byte(code >> 8), '#'}
	p = append(p, state[:5]...)
	return append(p, msg...)
}

func cstring(p []byte, off int) (string, int) {
	if off >= len(p) {
		return "", len(p)
	}
	i := off
	for i < len(p) && p[i] != 0 {
		i++
	}
	if i < len(p) {
		return string(p[off:i]), i + 1
	}
	return string(p[off:i]), i
}

func lenenc(p []byte, off int) (uint64, int) {
	if off >= len(p) {
		return 0, off
	}
	switch b := p[off]; {
	case b < 0xfb:
		return uint64(b), off + 1
	case b == 0xfc && off+3 <= len(p):
		return uint64(binary.LittleEndian.Uint16(p[off+1:])), off + 3
	case b == 0xfd && off+4 <= len(p):
		return uint64(p[off+1]) | uint64(p[off+2])<<8 | uint64(p[off+3])<<16, off + 4
	case b == 0xfe && off+9 <= len(p):
		return binary.LittleEndian.Uint64(p[off+1:]), off + 9
	}
	return 0, len(p)
}

func putLenenc(p []byte, v uint64) []byte {
	switch {
	case v < 0xfb:
		return append(p, byte(v))
	case v < 1<<16:
		return append(p, 0xfc, byte(v), byte(v>>8))
	case v < 1<<24:
		return append(p, 0xfd, byte(v), byte(v>>8), byte(v>>16))
	}
	p = append(p, 0xfe)
	return binary.LittleEndian.AppendUint64(p, v)
}

// okStatus reads affected rows and the status flags of an OK packet
// (header 0x00, or 0xfe as the end of a result set with DEPRECATE_EOF).
func okStatus(p []byte) (int64, uint16) {
	rows, off := lenenc(p, 1)
	_, off = lenenc(p, off)
	if off+2 > len(p) {
		return int64(rows), 0
	}
	return int64(rows), binary.LittleEndian.Uint16(p[off:])
}

func errMessage(p []byte) string {
	if len(p) < 3 {
		return "error"
	}
	code := binary.LittleEndian.Uint16(p[1:])
	msg := p[3:]
	if len(msg) >= 6 && msg[0] == '#' {
		return fmt.Sprintf("%d (%s) %s", code, msg[1:6], msg[6:])
	}
	return fmt.Sprintf("%d %s", code, msg)
}

func scrambleSalt() []byte {
	s := make([]byte, 20)
	_, _ = rand.Read(s)
	for i := range s {
		s[i] = s[i]%127 + 1 // printable-ish and never NUL, like MySQL's
	}
	return s
}

// handleMySQL serves one MySQL/MariaDB client until either side closes.
func handleMySQL(raw net.Conn, core *Core, tlsCfg *tls.Config) {
	defer raw.Close()
	clientIP, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	cl := newMconn(raw)
	salt := scrambleSalt()

	hs := []byte{10}
	hs = append(hs, proxyServerVersion...)
	hs = append(hs, 0)
	hs = binary.LittleEndian.AppendUint32(hs, mysqlConnID.Add(1))
	hs = append(hs, salt[:8]...)
	hs = append(hs, 0)
	hs = binary.LittleEndian.AppendUint16(hs, uint16(offeredCaps&0xffff))
	hs = append(hs, defaultCollation)
	hs = binary.LittleEndian.AppendUint16(hs, 2) // autocommit
	hs = binary.LittleEndian.AppendUint16(hs, uint16(offeredCaps>>16))
	hs = append(hs, 21)
	hs = append(hs, make([]byte, 10)...)
	hs = append(hs, salt[8:]...)
	hs = append(hs, 0)
	hs = append(hs, "caching_sha2_password"...)
	hs = append(hs, 0)
	if cl.send(0, hs) != nil {
		return
	}

	p, _, seq, err := cl.read()
	if err != nil || len(p) < 32 {
		return
	}
	caps := binary.LittleEndian.Uint32(p)
	if caps&capProtocol41 == 0 {
		_ = cl.send(seq+1, errPacket(errHandshake, "08S01", "bastion: this client is too old (no 4.1 protocol)"))
		return
	}
	if caps&capSSL == 0 || len(p) != 32 {
		_ = cl.send(seq+1, errPacket(errAccessDenied, "28000", "bastion: TLS is required (--ssl / ssl-mode=REQUIRED)"))
		return
	}
	tc := tls.Server(raw, tlsCfg)
	if err := tc.Handshake(); err != nil {
		logger.Info("TLS handshake failed", "client", clientIP, "error", err)
		return
	}
	cl = newMconn(tc)
	p, _, seq, err = cl.read()
	if err != nil || len(p) < 32 {
		return
	}
	caps = binary.LittleEndian.Uint32(p) & offeredCaps
	charset := p[8]
	off := 32
	_, off = cstring(p, off) // the user name: the token says who it is
	var authResp []byte
	switch {
	case caps&capPluginAuthLenenc != 0:
		var n uint64
		n, off = lenenc(p, off)
		end := min(off+int(n), len(p))
		authResp, off = p[off:end], end
	case caps&capSecureConn != 0 && off < len(p):
		n := int(p[off])
		end := min(off+1+n, len(p))
		authResp, off = p[off+1:end], end
	default:
		var s string
		s, off = cstring(p, off)
		authResp = []byte(s)
	}
	clientDB := ""
	if caps&capConnectWithDB != 0 {
		clientDB, off = cstring(p, off)
	}
	plugin := ""
	if caps&capPluginAuth != 0 {
		plugin, _ = cstring(p, off)
	}

	// Get the token in clear (we are inside TLS).
	next := seq + 1
	var token string
	switch plugin {
	case "mysql_clear_password":
		token = string(authResp)
	case "caching_sha2_password":
		if len(authResp) == 0 {
			_ = cl.send(next, errPacket(errAccessDenied, "28000", "bastion: use your bastion DB token as the password"))
			return
		}
		// "Perform full authentication": over TLS the client sends the
		// password itself.
		if cl.send(next, []byte{0x01, 0x04}) != nil {
			return
		}
		if p, _, seq, err = cl.read(); err != nil {
			return
		}
		token, next = string(p), seq+1
	default:
		sw := append([]byte{0xfe}, "mysql_clear_password"...)
		sw = append(sw, 0)
		if cl.send(next, sw) != nil {
			return
		}
		if p, _, seq, err = cl.read(); err != nil {
			return
		}
		token, next = string(p), seq+1
	}
	token = strings.TrimSpace(strings.TrimRight(token, "\x00"))

	ctx := context.Background()
	res, err := core.Connect(ctx, token, clientIP, "mysql")
	if err != nil {
		logger.Info("connection refused", "client", clientIP, "reason", err)
		_ = cl.send(next, errPacket(errAccessDenied, "28000", "bastion: "+err.Error()))
		return
	}
	defer core.Disconnect(res.SessionID)
	t := res.Target
	if t.Database == "" {
		t.Database = clientDB
	}
	sv, err := connectMySQL(ctx, t, caps, charset, "mybastion "+res.Actor)
	if err != nil {
		logger.Info("database connection failed", "client", clientIP, "actor", res.Actor, "error", err)
		_ = cl.send(next, errPacket(errConnect, "HY000", "bastion: cannot connect to the database: "+err.Error()))
		return
	}
	defer sv.conn.c.Close()
	if caps&wireCaps != sv.caps&wireCaps {
		_ = cl.send(next, errPacket(errHandshake, "08S01", fmt.Sprintf(
			"bastion: the database server does not support this client's protocol options (%#x)", (caps^sv.caps)&wireCaps)))
		return
	}
	ok := []byte{0x00, 0, 0}
	ok = binary.LittleEndian.AppendUint16(ok, sv.status)
	ok = append(ok, 0, 0)
	if cl.send(next, ok) != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	logger.Info("connected", "client", clientIP, "actor", res.Actor, "session", res.SessionID, "server", sv.version)

	s := &mysqlSession{
		core: core, id: res.SessionID, client: cl, server: sv.conn,
		eofDeprecated: caps&capDeprecateEOF != 0, prepared: map[uint32]Stmt{},
	}
	s.relay()
	cl.c.Close()
	sv.conn.c.Close()
	// The deferred core.Disconnect runs after this: let the audits land first.
	s.audits.Wait()
}

type mysqlServer struct {
	conn    *mconn
	caps    uint32
	status  uint16
	version string
}

func nativePassword(salt []byte, pw string) []byte {
	if pw == "" {
		return nil
	}
	h1 := sha1.Sum([]byte(pw))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(salt[:20])
	h.Write(h2[:])
	h3 := h.Sum(nil)
	for i := range h3 {
		h3[i] ^= h1[i]
	}
	return h3
}

func cachingSha2Password(salt []byte, pw string) []byte {
	if pw == "" {
		return nil
	}
	m1 := sha256.Sum256([]byte(pw))
	m2 := sha256.Sum256(m1[:])
	h := sha256.New()
	h.Write(m2[:])
	h.Write(salt[:20])
	m3 := h.Sum(nil)
	for i := range m3 {
		m3[i] ^= m1[i]
	}
	return m3
}

// rsaPassword encrypts the password for sha256/caching_sha2 full auth
// without TLS, with the server's public key.
func rsaPassword(pemKey []byte, salt []byte, pw string) ([]byte, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, errors.New("the server sent no public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the server's public key is not RSA")
	}
	plain := append([]byte(pw), 0)
	for i := range plain {
		plain[i] ^= salt[i%20]
	}
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plain, nil)
}

// connectMySQL logs in to the real server with the entry's credentials,
// with the client's protocol options. TLS is used when the server offers
// it (not verified, like PostgreSQL's sslmode=prefer).
func connectMySQL(ctx context.Context, t Target, clientCaps uint32, charset byte, program string) (*mysqlServer, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*mysqlServer, error) {
		nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Now().Add(30 * time.Second))
	m := newMconn(nc)
	p, _, _, err := m.read()
	if err != nil {
		return fail(err)
	}
	if len(p) > 0 && p[0] == 0xff {
		return fail(errors.New(errMessage(p)))
	}
	if len(p) < 1 || p[0] != 10 {
		return fail(errors.New("not a MySQL server (unknown handshake)"))
	}
	version, off := cstring(p, 1)
	if off+4+8+1+2 > len(p) {
		return fail(errors.New("short handshake"))
	}
	off += 4
	salt := append([]byte{}, p[off:off+8]...)
	off += 9
	srvCaps := uint32(binary.LittleEndian.Uint16(p[off:]))
	off += 2
	plugin := "mysql_native_password"
	if off+16 <= len(p) {
		off++ // charset
		off += 2
		srvCaps |= uint32(binary.LittleEndian.Uint16(p[off:])) << 16
		off += 2
		authLen := int(p[off])
		off += 11
		n := max(13, authLen-8)
		end := min(off+n, len(p))
		salt = append(salt, p[off:end]...)
		off = end
		if srvCaps&capPluginAuth != 0 {
			plugin, _ = cstring(p, off)
		}
	}
	salt = []byte(strings.TrimRight(string(salt), "\x00"))
	if len(salt) < 20 {
		salt = append(salt, make([]byte, 20-len(salt))...)
	}
	need := uint32(capProtocol41 | capSecureConn | capPluginAuth)
	if srvCaps&need != need {
		return fail(fmt.Errorf("server %s is too old for the bastion", version))
	}
	// MariaDB does not know MySQL 8's default collation (255).
	if strings.Contains(version, "MariaDB") && charset > 247 {
		charset = defaultCollation
	}
	caps := clientCaps&offeredCaps&^(capSSL|capConnectWithDB|capConnectAttrs) |
		capLongPassword | capProtocol41 | capSecureConn | capPluginAuth
	caps |= srvCaps & (capPluginAuthLenenc | capConnectAttrs)
	if t.Database != "" {
		caps |= capConnectWithDB
	}
	caps &= srvCaps
	seq := byte(1)
	secure := false
	if srvCaps&capSSL != 0 {
		req := binary.LittleEndian.AppendUint32(nil, caps|capSSL)
		req = binary.LittleEndian.AppendUint32(req, 1<<24)
		req = append(req, charset)
		req = append(req, make([]byte, 23)...)
		if err := m.send(seq, req); err != nil {
			return fail(err)
		}
		tc := tls.Client(nc, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // like sslmode=prefer
		if err := tc.HandshakeContext(ctx); err != nil {
			return fail(fmt.Errorf("TLS to the server: %w", err))
		}
		m = newMconn(tc)
		caps |= capSSL
		secure = true
		seq++
	}
	auth, err := authData(plugin, salt, t.Password, secure)
	if err != nil {
		return fail(err)
	}
	resp := binary.LittleEndian.AppendUint32(nil, caps)
	resp = binary.LittleEndian.AppendUint32(resp, 1<<24)
	resp = append(resp, charset)
	resp = append(resp, make([]byte, 23)...)
	resp = append(resp, t.User...)
	resp = append(resp, 0)
	if caps&capPluginAuthLenenc != 0 {
		resp = putLenenc(resp, uint64(len(auth)))
	} else {
		resp = append(resp, byte(len(auth)))
	}
	resp = append(resp, auth...)
	if caps&capConnectWithDB != 0 {
		resp = append(resp, t.Database...)
		resp = append(resp, 0)
	}
	resp = append(resp, plugin...)
	resp = append(resp, 0)
	if caps&capConnectAttrs != 0 {
		var attrs []byte
		for _, kv := range [][2]string{{"_client_name", "mybastion-dbproxy"}, {"program_name", program}} {
			attrs = putLenenc(attrs, uint64(len(kv[0])))
			attrs = append(attrs, kv[0]...)
			attrs = putLenenc(attrs, uint64(len(kv[1])))
			attrs = append(attrs, kv[1]...)
		}
		resp = putLenenc(resp, uint64(len(attrs)))
		resp = append(resp, attrs...)
	}
	if err := m.send(seq, resp); err != nil {
		return fail(err)
	}
	for {
		p, _, seq, err = m.read()
		if err != nil {
			return fail(err)
		}
		if len(p) == 0 {
			return fail(errors.New("empty packet during login"))
		}
		var reply []byte
		switch p[0] {
		case 0x00:
			_, status := okStatus(p)
			_ = nc.SetDeadline(time.Time{})
			return &mysqlServer{conn: m, caps: caps, status: status, version: version}, nil
		case 0xff:
			return fail(errors.New(errMessage(p)))
		case 0xfe: // auth switch
			if len(p) == 1 {
				return fail(errors.New("the server wants the old (pre-4.1) password scheme"))
			}
			var o int
			plugin, o = cstring(p, 1)
			salt = []byte(strings.TrimRight(string(p[o:]), "\x00"))
			if len(salt) < 20 {
				salt = append(salt, make([]byte, 20-len(salt))...)
			}
			if reply, err = authData(plugin, salt, t.Password, secure); err != nil {
				return fail(err)
			}
		case 0x01: // more data
			switch {
			case plugin == "caching_sha2_password" && len(p) == 2 && p[1] == 0x03:
				continue // fast auth worked; OK follows
			case plugin == "caching_sha2_password" && len(p) == 2 && p[1] == 0x04:
				if secure {
					reply = append([]byte(t.Password), 0)
				} else {
					reply = []byte{0x02} // ask for the public key
				}
			case plugin == "caching_sha2_password" || plugin == "sha256_password":
				if reply, err = rsaPassword(p[1:], salt, t.Password); err != nil {
					return fail(err)
				}
			default:
				return fail(fmt.Errorf("unexpected login data for %s", plugin))
			}
		default:
			return fail(fmt.Errorf("unexpected login packet %#x", p[0]))
		}
		if err := m.send(seq+1, reply); err != nil {
			return fail(err)
		}
	}
}

// authData is the first auth response for a server's plugin.
func authData(plugin string, salt []byte, pw string, secure bool) ([]byte, error) {
	switch plugin {
	case "mysql_native_password":
		return nativePassword(salt, pw), nil
	case "caching_sha2_password":
		return cachingSha2Password(salt, pw), nil
	case "sha256_password":
		if secure {
			return append([]byte(pw), 0), nil
		}
		return []byte{0x01}, nil // ask for the public key
	case "mysql_clear_password":
		if !secure {
			return nil, errors.New("the server wants the password in clear without TLS")
		}
		return append([]byte(pw), 0), nil
	}
	return nil, fmt.Errorf("the server's authentication plugin %q is not supported by the bastion", plugin)
}

// ── After login ──

type mysqlSession struct {
	core          *Core
	id            string
	client        *mconn
	server        *mconn
	eofDeprecated bool
	prepared      map[uint32]Stmt
	lastPrepared  uint32
	audits        sync.WaitGroup
}

func (s *mysqlSession) audit(st Stmt, status string, rows int64, errMsg string) {
	s.audits.Add(1)
	go func() {
		defer s.audits.Done()
		s.core.Audit(s.id, st, status, rows, "", errMsg)
	}()
}

func (s *mysqlSession) refuse(msg string) error {
	return s.client.send(1, errPacket(errRefused, "42000", msg))
}

func (s *mysqlSession) check(stmts []Stmt) (string, bool) {
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

// parse a query for COM_QUERY / COM_STMT_PREPARE; refused if it cannot be.
func (s *mysqlSession) parse(sql string) ([]Stmt, bool) {
	stmts, err := SplitMySQL(sql)
	if err != nil {
		msg := err.Error()
		s.audit(Stmt{SQL: sql, Classes: []string{"other"}}, "refused", -1, "unparseable: "+msg)
		_ = s.refuse("bastion: this statement could not be parsed, so it was not run: " + msg)
		return nil, false
	}
	return stmts, true
}

func (s *mysqlSession) relay() {
	for {
		p, raw, _, err := s.client.read()
		if err != nil || len(p) == 0 {
			return
		}
		var queue []Stmt
		switch p[0] {
		case comQuit:
			_, _ = s.server.c.Write(raw)
			return
		case comQuery:
			stmts, ok := s.parse(string(p[1:]))
			if !ok {
				continue
			}
			if msg, ok := s.check(stmts); !ok {
				if s.refuse(msg) != nil {
					return
				}
				continue
			}
			queue = stmts
		case comInitDB:
			st := Stmt{SQL: "USE `" + strings.ReplaceAll(string(p[1:]), "`", "``") + "`", Classes: []string{"session"}}
			if msg, ok := s.check([]Stmt{st}); !ok {
				if s.refuse(msg) != nil {
					return
				}
				continue
			}
			queue = []Stmt{st}
		case comStmtPrepare:
			stmts, ok := s.parse(string(p[1:]))
			if !ok {
				continue
			}
			if len(stmts) != 1 {
				if s.refuse("bastion: a prepared statement must be a single statement") != nil {
					return
				}
				continue
			}
			if msg, ok := s.check(stmts); !ok {
				if s.refuse(msg) != nil {
					return
				}
				continue
			}
			if _, err := s.server.c.Write(raw); err != nil {
				return
			}
			if s.prepareResponse(stmts[0]) != nil {
				return
			}
			continue
		case comStmtExecute:
			if len(p) < 6 {
				return
			}
			if p[5] != 0 {
				if s.refuse("bastion: server-side cursors are not supported through the bastion") != nil {
					return
				}
				continue
			}
			id := binary.LittleEndian.Uint32(p[1:])
			if id == 0xffffffff { // MariaDB: the statement prepared last
				id = s.lastPrepared
			}
			st, ok := s.prepared[id]
			if !ok {
				st = Stmt{SQL: "(unknown prepared statement " + strconv.Itoa(int(id)) + ")", Classes: []string{"other"}}
			}
			queue = []Stmt{st}
		case comStmtClose, comStmtSendLong:
			if p[0] == comStmtClose && len(p) >= 5 {
				delete(s.prepared, binary.LittleEndian.Uint32(p[1:]))
			}
			// No response to these.
			if _, err := s.server.c.Write(raw); err != nil {
				return
			}
			continue
		case comPing, comStatistics, comStmtReset, comSetOption, comResetConnection:
			if p[0] == comResetConnection {
				clear(s.prepared)
			}
			if _, err := s.server.c.Write(raw); err != nil {
				return
			}
			if s.single() != nil {
				return
			}
			continue
		case comFieldList:
			if _, err := s.server.c.Write(raw); err != nil {
				return
			}
			if s.untilEOF() != nil {
				return
			}
			continue
		default:
			if s.refuse(fmt.Sprintf("bastion: this command (%#x) is not supported through the bastion", p[0])) != nil {
				return
			}
			continue
		}
		if _, err := s.server.c.Write(raw); err != nil {
			return
		}
		if s.results(queue) != nil {
			return
		}
	}
}

// fromServer reads one packet from the server and passes it on (buffered).
func (s *mysqlSession) fromServer() ([]byte, error) {
	p, raw, _, err := s.server.read()
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, errors.New("empty packet from the server")
	}
	if _, err := s.client.w.Write(raw); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *mysqlSession) single() error {
	if _, err := s.fromServer(); err != nil {
		return err
	}
	return s.client.w.Flush()
}

// untilEOF relays packets up to an EOF/OK (0xfe) or ERR (COM_FIELD_LIST).
func (s *mysqlSession) untilEOF() error {
	for {
		p, err := s.fromServer()
		if err != nil {
			return err
		}
		if p[0] == 0xff || (p[0] == 0xfe && len(p) < 0xffffff) {
			return s.client.w.Flush()
		}
	}
}

// skip relays n column definitions and the EOF after them (if not
// deprecated).
func (s *mysqlSession) skip(n uint64) error {
	for i := uint64(0); i < n; i++ {
		if _, err := s.fromServer(); err != nil {
			return err
		}
	}
	if n > 0 && !s.eofDeprecated {
		if _, err := s.fromServer(); err != nil {
			return err
		}
	}
	return nil
}

func (s *mysqlSession) prepareResponse(st Stmt) error {
	p, err := s.fromServer()
	if err != nil {
		return err
	}
	if p[0] == 0x00 && len(p) >= 9 {
		id := binary.LittleEndian.Uint32(p[1:])
		cols := binary.LittleEndian.Uint16(p[5:])
		params := binary.LittleEndian.Uint16(p[7:])
		if err := s.skip(uint64(params)); err != nil {
			return err
		}
		if err := s.skip(uint64(cols)); err != nil {
			return err
		}
		s.prepared[id] = st
		s.lastPrepared = id
	}
	return s.client.w.Flush()
}

// results relays the response to a query or execute: one result (OK, ERR
// or a result set) per statement, and more while the server says so. A
// procedure's several results are counted for its one statement.
func (s *mysqlSession) results(queue []Stmt) error {
	idx := 0
	var total int64
	current := func() (Stmt, bool) {
		if len(queue) == 0 {
			return Stmt{}, false
		}
		return queue[min(idx, len(queue)-1)], true
	}
	// done records one result; more says whether another follows.
	done := func(rows int64, more bool) {
		st, ok := current()
		if !ok {
			return
		}
		if rows > 0 {
			total += rows
		}
		if idx < len(queue)-1 || !more {
			s.audit(st, "ok", total, "")
			total = 0
			idx++
		}
	}
	for {
		p, err := s.fromServer()
		if err != nil {
			return err
		}
		var status uint16
		switch {
		case p[0] == 0x00:
			var rows int64
			rows, status = okStatus(p)
			done(rows, status&statusMoreResults != 0)
		case p[0] == 0xff:
			if st, ok := current(); ok {
				s.audit(st, "error", -1, errMessage(p))
			}
			return s.client.w.Flush()
		case p[0] == 0xfb:
			return errors.New("the server asked for a local file (LOAD DATA LOCAL is not offered)")
		default:
			cols, _ := lenenc(p, 0)
			if err := s.skip(cols); err != nil {
				return err
			}
			var rows int64
			for {
				p, err := s.fromServer()
				if err != nil {
					return err
				}
				if p[0] == 0xfe && len(p) < 0xffffff && (s.eofDeprecated || len(p) < 9) {
					if s.eofDeprecated {
						_, status = okStatus(p)
					} else if len(p) >= 5 {
						status = binary.LittleEndian.Uint16(p[3:])
					}
					break
				}
				if p[0] == 0xff {
					if st, ok := current(); ok {
						s.audit(st, "error", -1, errMessage(p))
					}
					return s.client.w.Flush()
				}
				rows++
			}
			done(rows, status&statusMoreResults != 0)
		}
		if status&statusMoreResults == 0 {
			return s.client.w.Flush()
		}
	}
}

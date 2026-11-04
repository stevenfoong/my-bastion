package main

// The core's internal API (/internal/db/...), authenticated with the
// shared secret. Policy, credentials and audit live there.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Core struct {
	URL    string
	Secret string
	HTTP   *http.Client
}

type Target struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
}

type ConnectResult struct {
	SessionID string `json:"session_id"`
	Actor     string `json:"actor"`
	Target    Target `json:"target"`
}

type CheckResult struct {
	Decision   string `json:"decision"` // allow | deny | pending
	Message    string `json:"message"`
	ApprovalID string `json:"approval_id"`
}

// apiError is a refusal from the core, with the message to show the user.
type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return e.Msg }

func (c *Core) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Mybastion-Proxy-Secret", c.Secret)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("the bastion cannot be reached: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return &apiError{Status: resp.StatusCode, Msg: e.Error}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Connect checks a token; protocol is the listener it came in on
// ("postgres" or "mysql"), which must be the entry's type.
func (c *Core) Connect(ctx context.Context, token, clientIP, protocol string) (*ConnectResult, error) {
	var r ConnectResult
	err := c.post(ctx, "/internal/db/connect", map[string]string{"token": token, "client_ip": clientIP, "protocol": protocol}, &r)
	return &r, err
}

func (c *Core) Check(ctx context.Context, session string, s Stmt) (*CheckResult, error) {
	var r CheckResult
	err := c.post(ctx, "/internal/db/check", map[string]any{
		"session_id": session, "statement": s.SQL, "classes": s.Classes,
	}, &r)
	return &r, err
}

// Audit records how a statement ended: status ok, error or refused.
func (c *Core) Audit(session string, s Stmt, status string, rows int64, tag, errMsg string) {
	in := map[string]any{"session_id": session, "statement": s.SQL, "classes": s.Classes, "status": status}
	if rows >= 0 {
		in["rows"] = rows
	}
	if tag != "" {
		in["tag"] = tag
	}
	if errMsg != "" {
		in["error"] = errMsg
	}
	if err := c.post(context.Background(), "/internal/db/audit", in, nil); err != nil {
		logger.Warn("audit failed", "error", err)
	}
}

func (c *Core) Disconnect(session string) {
	_ = c.post(context.Background(), "/internal/db/disconnect", map[string]string{"session_id": session}, nil)
}

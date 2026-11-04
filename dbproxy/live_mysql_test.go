//go:build live

package main

// Live check of the MySQL path with a real driver (go-sql-driver/mysql):
// prepared statements (COM_STMT_PREPARE/EXECUTE, binary rows) and
// multi-statement strings. Run by tests/test_dbproxy_mysql.sh with
// MYSQL_PROXY_DSN set: go test -tags live -run Live ./...

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

func liveDB(t *testing.T, extra string) *sql.DB {
	dsn := os.Getenv("MYSQL_PROXY_DSN")
	if dsn == "" {
		t.Skip("MYSQL_PROXY_DSN not set")
	}
	db, err := sql.Open("mysql", dsn+extra)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestLiveMySQLPrepared(t *testing.T) {
	db := liveDB(t, "")
	var n int
	if err := db.QueryRow("SELECT count(*) FROM t WHERE id > ?", 1).Scan(&n); err != nil || n != 2 {
		t.Fatalf("prepared SELECT: %d %v", n, err)
	}
	var v string
	if err := db.QueryRow("SELECT v FROM t WHERE id = ?", 1).Scan(&v); err != nil || v != "a" {
		t.Fatalf("prepared SELECT of a string (binary rows): %q %v", v, err)
	}
	res, err := db.Exec("UPDATE t SET v = ? WHERE id = ?", "p", 2)
	if err != nil {
		t.Fatalf("prepared UPDATE: %v", err)
	}
	if r, _ := res.RowsAffected(); r != 1 {
		t.Fatalf("prepared UPDATE rows: %d", r)
	}
	if _, err := db.Prepare("DELETE FROM t"); err == nil || !strings.Contains(err.Error(), "no unbounded writes") {
		t.Fatalf("prepared unbounded DELETE: %v", err)
	}
	// The connection is still usable after a refusal.
	if err := db.QueryRow("SELECT count(*) FROM t WHERE id >= ?", 0).Scan(&n); err != nil || n != 3 {
		t.Fatalf("after a refusal: %d %v", n, err)
	}
}

func TestLiveMySQLMultiStatements(t *testing.T) {
	db := liveDB(t, "&multiStatements=true")
	_, err := db.Exec("SELECT 1; DELETE FROM t")
	if err == nil || !strings.Contains(err.Error(), "no unbounded writes") {
		t.Fatalf("multi-statement with an unbounded DELETE: %v", err)
	}
	if _, err := db.Exec("UPDATE t SET v = 'm' WHERE id = 3; UPDATE t SET v = 'n' WHERE id = 3"); err != nil {
		t.Fatalf("two bounded updates: %v", err)
	}
	var v string
	if err := db.QueryRow("SELECT v FROM t WHERE id = 3").Scan(&v); err != nil || v != "n" {
		t.Fatalf("after two updates: %q %v", v, err)
	}
}

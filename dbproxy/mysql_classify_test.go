package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestMySQLClasses(t *testing.T) {
	cases := map[string]string{
		"SELECT * FROM t WHERE id = 1":                "read",
		"select @@version_comment limit 1":            "read",
		"SHOW TABLES":                                 "read",
		"SELECT 1 UNION SELECT 2":                     "read",
		"SELECT * FROM t INTO OUTFILE '/tmp/x'":       "admin,read",
		"INSERT INTO t VALUES (1)":                    "write",
		"REPLACE INTO t VALUES (1)":                   "write",
		"UPDATE t SET a = 1 WHERE id = 2":             "write",
		"UPDATE t SET a = 1":                          "unbounded,write",
		"DELETE FROM t":                               "unbounded,write",
		"DELETE FROM t WHERE id = 3 LIMIT 1":          "write",
		"TRUNCATE TABLE t":                            "ddl,unbounded,write",
		"LOAD DATA INFILE '/etc/passwd' INTO TABLE t": "admin,write",
		"CREATE TABLE t (id int)":                     "ddl",
		"CREATE TABLE t2 AS SELECT * FROM t":          "ddl,write",
		"ALTER TABLE t ADD COLUMN b int":              "ddl",
		"DROP TABLE t":                                "ddl",
		"CREATE INDEX i ON t (a)":                     "ddl",
		"CREATE DATABASE x":                           "admin",
		"GRANT SELECT ON *.* TO 'u'@'%'":              "admin",
		"CREATE USER 'u'@'%' IDENTIFIED BY 'p'":       "admin",
		"FLUSH PRIVILEGES":                            "admin",
		"KILL 3":                                      "admin",
		"SET GLOBAL max_connections = 10":             "admin,session",
		"SET NAMES utf8mb4":                           "session",
		"SET autocommit = 0":                          "session",
		"BEGIN":                                       "session",
		"COMMIT":                                      "session",
		"USE db":                                      "session",
		"CALL p()":                                    "procedure",
		"DO sleep(1)":                                 "procedure",
		"PREPARE s FROM 'DELETE FROM t'":              "unbounded,write",
		"PREPARE s FROM @q":                           "procedure",
		"EXPLAIN SELECT * FROM t":                     "read",
		"LOCK TABLES t WRITE":                         "write",
		"/*!40101 SET NAMES utf8 */":                  "session",
	}
	for sql, want := range cases {
		got, err := SplitMySQL(sql)
		if err != nil {
			t.Errorf("%q: %v", sql, err)
			continue
		}
		if len(got) != 1 {
			t.Errorf("%q: %d statements", sql, len(got))
			continue
		}
		if g := strings.Join(got[0].Classes, ","); g != want {
			t.Errorf("%q: got %s, want %s", sql, g, want)
		}
	}
}

func TestMySQLSplit(t *testing.T) {
	got, err := SplitMySQL("SELECT 1; DELETE FROM t ;")
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, s := range got {
		texts = append(texts, s.SQL)
	}
	if want := []string{"SELECT 1", "DELETE FROM t"}; !reflect.DeepEqual(texts, want) {
		t.Fatalf("got %q, want %q", texts, want)
	}
	if _, err := SplitMySQL("SELEC nonsense"); err == nil {
		t.Fatal("nonsense parsed")
	}
}

func TestMySQLScrambles(t *testing.T) {
	salt := []byte("abcdefghijklmnopqrst")
	if len(nativePassword(salt, "pw")) != 20 || nativePassword(salt, "") != nil {
		t.Fatal("native scramble")
	}
	if len(cachingSha2Password(salt, "pw")) != 32 {
		t.Fatal("caching_sha2 scramble")
	}
	if v, off := lenenc(putLenenc(nil, 70000), 0); v != 70000 || off != 4 {
		t.Fatalf("lenenc %d %d", v, off)
	}
}

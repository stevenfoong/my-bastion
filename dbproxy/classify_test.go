package main

import (
	"reflect"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		sql  string
		want []string
	}{
		{"SELECT * FROM t WHERE id = 1", []string{"read"}},
		{"insert into t values (1)", []string{"write"}},
		{"UPDATE t SET a = 1 WHERE id = 2", []string{"write"}},
		{"UPDATE t SET a = 1", []string{"unbounded", "write"}},
		{"DELETE FROM t", []string{"unbounded", "write"}},
		{"DELETE FROM t WHERE id = 3", []string{"write"}},
		{"TRUNCATE t", []string{"ddl", "unbounded", "write"}},
		{"DROP TABLE t", []string{"ddl"}},
		{"ALTER TABLE t ADD COLUMN b int", []string{"ddl"}},
		{"CREATE INDEX i ON t (a)", []string{"ddl"}},
		{"GRANT SELECT ON t TO bob", []string{"admin"}},
		{"CREATE ROLE bob", []string{"admin"}},
		{"VACUUM t", []string{"admin"}},
		{"CALL p()", []string{"procedure"}},
		{"DO $$ BEGIN END $$", []string{"procedure"}},
		{"EXECUTE s", []string{"procedure"}},
		{"BEGIN", []string{"session"}},
		{"SET search_path = x", []string{"session"}},
		{"SHOW server_version", []string{"session"}},
		{"COPY t TO STDOUT", []string{"read"}},
		{"COPY t FROM STDIN", []string{"write"}},
		{"COPY t TO PROGRAM 'cat'", []string{"admin"}},
		{"WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x", []string{"read", "unbounded", "write"}},
		{"SELECT * INTO t2 FROM t", []string{"ddl", "read", "write"}},
		{"PREPARE p AS DELETE FROM t WHERE id = $1", []string{"write"}},
		{"EXPLAIN DELETE FROM t", []string{"read"}},
		{"EXPLAIN ANALYZE DELETE FROM t", []string{"read", "unbounded", "write"}},
	}
	for _, c := range cases {
		got, err := Split(c.sql)
		if err != nil {
			t.Fatalf("%q: %v", c.sql, err)
		}
		if len(got) != 1 || !reflect.DeepEqual(got[0].Classes, c.want) {
			t.Errorf("%q: got %+v, want %v", c.sql, got, c.want)
		}
	}
}

func TestSplitKeepsEachStatementsText(t *testing.T) {
	got, err := Split("SELECT 1; DELETE FROM t WHERE a = 'x;y' ;  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].SQL != "SELECT 1" || got[1].SQL != "DELETE FROM t WHERE a = 'x;y'" {
		t.Fatalf("%+v", got)
	}
	if _, err := Split("SELEC 1"); err == nil {
		t.Fatal("garbage parsed")
	}
	if got, _ := Split(""); len(got) != 0 {
		t.Fatalf("empty: %+v", got)
	}
}

func TestRowsFromTag(t *testing.T) {
	for tag, want := range map[string]int64{"INSERT 0 5": 5, "UPDATE 3": 3, "SELECT 10": 10, "CREATE TABLE": -1, "": -1} {
		if got := rowsFromTag(tag); got != want {
			t.Errorf("%q: %d", tag, got)
		}
	}
}

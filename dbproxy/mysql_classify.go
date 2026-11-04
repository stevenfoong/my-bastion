package main

// Statement classification for MySQL and MariaDB with the TiDB SQL parser
// (a MySQL-dialect parser in pure Go). Same classes as for PostgreSQL:
// read, write, unbounded, ddl, admin, procedure, session, other.
//
// A statement the parser cannot read is refused, as for PostgreSQL; that
// includes some MariaDB-only syntax.

import (
	"sort"
	"strings"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver"
)

// SplitMySQL parses a query string into its statements.
func SplitMySQL(sql string) ([]Stmt, error) {
	// A parser is not safe for concurrent use; they are cheap to make.
	nodes, _, err := parser.New().ParseSQL(sql)
	if err != nil {
		return nil, err
	}
	out := make([]Stmt, 0, len(nodes))
	for _, n := range nodes {
		text := strings.TrimSpace(n.Text())
		text = strings.TrimSpace(strings.TrimSuffix(text, ";"))
		out = append(out, Stmt{SQL: text, Classes: mysqlClasses(n)})
	}
	return out, nil
}

func mysqlClasses(n ast.StmtNode) []string {
	set := map[string]bool{}
	addMySQL(set, n)
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	if len(out) == 0 {
		out = []string{"other"}
	}
	return out
}

func addMySQL(set map[string]bool, n ast.StmtNode) {
	switch s := n.(type) {
	case *ast.SelectStmt:
		set["read"] = true
		// SELECT ... INTO OUTFILE / DUMPFILE writes a file on the server.
		if s.SelectIntoOpt != nil && s.SelectIntoOpt.Tp != ast.SelectIntoVars {
			set["admin"] = true
		}
	case *ast.SetOprStmt, *ast.ShowStmt, *ast.ExplainForStmt, *ast.HelpStmt:
		set["read"] = true
	case *ast.InsertStmt:
		set["write"] = true
	case *ast.UpdateStmt:
		set["write"] = true
		if s.Where == nil {
			set["unbounded"] = true
		}
	case *ast.DeleteStmt:
		set["write"] = true
		if s.Where == nil {
			set["unbounded"] = true
		}
	case *ast.LoadDataStmt:
		set["write"] = true
		// Without LOCAL the server reads one of its own files.
		if s.FileLocRef != ast.FileLocClient {
			set["admin"] = true
		}
	case *ast.TruncateTableStmt:
		set["ddl"], set["write"], set["unbounded"] = true, true, true
	case *ast.LockTablesStmt:
		set["write"] = true
	case *ast.UnlockTablesStmt:
		set["session"] = true
	case *ast.CreateDatabaseStmt, *ast.AlterDatabaseStmt, *ast.DropDatabaseStmt,
		*ast.GrantStmt, *ast.GrantRoleStmt, *ast.GrantProxyStmt, *ast.RevokeStmt, *ast.RevokeRoleStmt,
		*ast.CreateUserStmt, *ast.AlterUserStmt, *ast.DropUserStmt, *ast.RenameUserStmt,
		*ast.SetPwdStmt, *ast.SetDefaultRoleStmt, *ast.FlushStmt, *ast.KillStmt,
		*ast.ShutdownStmt, *ast.RestartStmt, *ast.AdminStmt, *ast.AnalyzeTableStmt,
		*ast.OptimizeTableStmt, *ast.RepairTableStmt, *ast.BinlogStmt, *ast.AlterInstanceStmt,
		*ast.BRIEStmt, *ast.SetConfigStmt:
		set["admin"] = true
	case *ast.CallStmt, *ast.ExecuteStmt, *ast.DoStmt:
		set["procedure"] = true
	case *ast.PrepareStmt:
		// PREPARE ... FROM 'text' is classified by the text; FROM @var
		// could be anything.
		if s.SQLVar != nil {
			set["procedure"] = true
			return
		}
		inner, err := SplitMySQL(s.SQLText)
		if err != nil || len(inner) != 1 {
			set["procedure"] = true
			return
		}
		for _, c := range inner[0].Classes {
			set[c] = true
		}
	case *ast.ExplainStmt:
		set["read"] = true
		if s.Analyze && s.Stmt != nil {
			addMySQL(set, s.Stmt)
		}
	case *ast.SetStmt:
		set["session"] = true
		for _, v := range s.Variables {
			if v.IsGlobal || v.IsInstance {
				set["admin"] = true
			}
		}
	case *ast.BeginStmt, *ast.CommitStmt, *ast.RollbackStmt, *ast.SavepointStmt,
		*ast.ReleaseSavepointStmt, *ast.UseStmt, *ast.DeallocateStmt, *ast.SetRoleStmt,
		*ast.SetSessionStatesStmt:
		set["session"] = true
	case *ast.CreateTableStmt:
		set["ddl"] = true
		if s.Select != nil {
			set["write"] = true
		}
	case ast.DDLNode:
		set["ddl"] = true
	default:
		set["other"] = true
	}
}

package main

// Statement classification with the real PostgreSQL parser (pg_query): a
// query string is split into its statements, and each is given the classes
// the core's db_query policies match on.
//
// Classes: read, write, unbounded (UPDATE or DELETE without WHERE, and
// TRUNCATE), ddl, admin, procedure (CALL, DO, EXECUTE), session (BEGIN,
// SET, SHOW, ...), other. PREPARE, EXPLAIN and DECLARE CURSOR are
// classified by the statement they wrap (EXPLAIN ANALYZE runs it).
//
// Limits: a function called from a SELECT can change data, and a procedure
// or EXECUTE can run anything; those are what the procedure class is for.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// Stmt is one statement of a query string.
type Stmt struct {
	SQL     string
	Classes []string
}

var adminNodes = map[string]bool{
	"GrantStmt": true, "GrantRoleStmt": true, "CreateRoleStmt": true, "AlterRoleStmt": true,
	"AlterRoleSetStmt": true, "DropRoleStmt": true, "VacuumStmt": true, "ReindexStmt": true,
	"ClusterStmt": true, "AlterSystemStmt": true, "CheckPointStmt": true, "LoadStmt": true,
	"CreatedbStmt": true, "DropdbStmt": true, "AlterDatabaseStmt": true, "AlterDatabaseSetStmt": true,
	"AlterDatabaseRefreshCollStmt": true, "CreateExtensionStmt": true, "AlterExtensionStmt": true,
	"AlterExtensionContentsStmt": true, "CreateTableSpaceStmt": true, "DropTableSpaceStmt": true,
	"AlterTableSpaceOptionsStmt": true, "ReassignOwnedStmt": true, "DropOwnedStmt": true,
	"CreateSubscriptionStmt": true, "AlterSubscriptionStmt": true, "DropSubscriptionStmt": true,
	"CreatePublicationStmt": true, "AlterPublicationStmt": true, "CreateEventTrigStmt": true,
	"AlterEventTrigStmt": true, "CreateFdwStmt": true, "AlterFdwStmt": true,
	"CreateForeignServerStmt": true, "AlterForeignServerStmt": true, "CreateUserMappingStmt": true,
	"AlterUserMappingStmt": true, "DropUserMappingStmt": true, "ImportForeignSchemaStmt": true,
	"AlterDefaultPrivilegesStmt": true, "SecLabelStmt": true,
}

var sessionNodes = map[string]bool{
	"TransactionStmt": true, "VariableSetStmt": true, "VariableShowStmt": true, "DiscardStmt": true,
	"ListenStmt": true, "UnlistenStmt": true, "DeallocateStmt": true, "FetchStmt": true,
	"ClosePortalStmt": true, "ConstraintsSetStmt": true,
}

var writeNodes = map[string]bool{
	"InsertStmt": true, "UpdateStmt": true, "DeleteStmt": true, "MergeStmt": true,
	"RefreshMatViewStmt": true, "LockStmt": true, "NotifyStmt": true,
}

// Split parses a query string into its statements. An error means the
// bastion cannot tell what it would do, and it is refused.
func Split(sql string) ([]Stmt, error) {
	tree, err := pg_query.ParseToJSON(sql)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Stmts []struct {
			Stmt     map[string]json.RawMessage `json:"stmt"`
			Location int                        `json:"stmt_location"`
			Len      int                        `json:"stmt_len"`
		} `json:"stmts"`
	}
	if err := json.Unmarshal([]byte(tree), &parsed); err != nil {
		return nil, fmt.Errorf("parse tree: %w", err)
	}
	out := make([]Stmt, 0, len(parsed.Stmts))
	for _, s := range parsed.Stmts {
		end := len(sql)
		if s.Len > 0 && s.Location+s.Len <= len(sql) {
			end = s.Location + s.Len
		}
		text := ""
		if s.Location <= end {
			text = strings.TrimSpace(sql[s.Location:end])
		}
		out = append(out, Stmt{SQL: text, Classes: classify(s.Stmt)})
	}
	return out, nil
}

// classify one statement node: {"NodeName": {...}}.
func classify(node map[string]json.RawMessage) []string {
	set := map[string]bool{}
	for name, body := range node {
		addClasses(set, name, body)
	}
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

func has(body json.RawMessage, key string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	v, ok := m[key]
	return ok && string(v) != "null"
}

func field(body json.RawMessage, key string) json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return nil
	}
	return m[key]
}

// inner classifies a wrapped statement (PREPARE ... AS, EXPLAIN, DECLARE).
func inner(set map[string]bool, body json.RawMessage, key string) {
	var n map[string]json.RawMessage
	if json.Unmarshal(field(body, key), &n) != nil {
		return
	}
	for name, b := range n {
		addClasses(set, name, b)
	}
}

func addClasses(set map[string]bool, name string, body json.RawMessage) {
	switch {
	case name == "SelectStmt":
		set["read"] = true
		// SELECT ... INTO creates a table; a CTE may change data.
		if has(body, "intoClause") {
			set["write"], set["ddl"] = true, true
		}
		for w := range writeNodes {
			if strings.Contains(string(body), `"`+w+`"`) {
				set["write"] = true
				if w != "InsertStmt" && !strings.Contains(string(body), `"whereClause"`) {
					set["unbounded"] = true
				}
			}
		}
	case name == "UpdateStmt" || name == "DeleteStmt":
		set["write"] = true
		if !has(body, "whereClause") {
			set["unbounded"] = true
		}
	case writeNodes[name]:
		set["write"] = true
	case name == "CopyStmt":
		switch {
		case has(body, "is_program"):
			set["admin"] = true
		case has(body, "is_from"):
			set["write"] = true
		default:
			set["read"] = true
		}
	case name == "TruncateStmt":
		set["ddl"], set["write"], set["unbounded"] = true, true, true
	case adminNodes[name]:
		set["admin"] = true
	case name == "CallStmt" || name == "DoStmt" || name == "ExecuteStmt":
		set["procedure"] = true
	case name == "PrepareStmt":
		inner(set, body, "query")
	case name == "ExplainStmt":
		set["read"] = true
		if strings.Contains(strings.ToLower(string(field(body, "options"))), `"analyze"`) {
			inner(set, body, "query")
		}
	case name == "DeclareCursorStmt":
		inner(set, body, "query")
	case sessionNodes[name]:
		set["session"] = true
	case name == "CreateTableAsStmt":
		set["ddl"], set["write"] = true, true
	case strings.HasPrefix(name, "Create") || strings.HasPrefix(name, "Alter") ||
		strings.HasPrefix(name, "Drop") || strings.HasPrefix(name, "Define") ||
		name == "RenameStmt" || name == "CommentStmt" || name == "IndexStmt" ||
		name == "ViewStmt" || name == "RuleStmt" || name == "CompositeTypeStmt":
		set["ddl"] = true
	default:
		set["other"] = true
	}
}

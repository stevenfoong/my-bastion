# Database proxy

`mybastion-dbproxy` (in `dbproxy/`, a separate Go service) puts database
access behind the bastion: people connect `psql`, DBeaver or any
PostgreSQL client to it with a short-lived **bastion DB token** as the
password, and every statement is checked against policy, held for
approval when a policy says so, and audited with who ran it and how many
rows it touched. The database's own credentials stay in the bastion.

PostgreSQL first; MySQL/MariaDB later.

## How it works

1. An admin adds a database entry (type `postgres`, with `hostname`,
   `port`, `username`, `password`, `database`) to a folder, like any other
   connection.
2. A user with access to the folder (operator or above) asks for a token:

   ```
   POST /api/addressbook/folders/{scope}/{folder}/entries/{entry}/db-token
   ```

   The entry's `connect` policies apply (a deny refuses, an approval
   waits). The answer has the token (`mbdb_…`, valid `token_minutes`,
   default 15) and the command to use:

   ```
   PGPASSWORD=<token> psql "host=bastion.example.com port=5433 dbname=app user=you@example.com sslmode=require"
   ```

3. The client connects to the proxy over **TLS** (required) and gives the
   token as its password. The proxy asks the core, which checks the token,
   the user (still enabled, still with access to the folder) and the
   connect policies again, and answers with the real credentials and the
   address (which must be in `[dbproxy] allowed_networks`). The proxy
   connects to the database itself; the user never sees its password.
4. Every statement, in a simple query or a prepared statement (the
   extended protocol's `Parse`), is parsed with PostgreSQL's own parser
   (`pg_query`), split if there are several, classified, and checked with
   the core's `db_query` policies before it is sent on. A statement that
   cannot be parsed is not run.
5. When the database answers, the outcome (rows, or the error) goes to the
   policy audit log: `db_query`, `db_query_failed`, `db_query_blocked`,
   with `db_connect` and `db_disconnect` around them.

## Policies

`db_query` rules match on the statement's **classes** and, optionally, on
regular expressions over its text (`commands`):

| Class | Statements |
|---|---|
| `read` | SELECT, COPY TO, EXPLAIN |
| `write` | INSERT, UPDATE, DELETE, MERGE, COPY FROM, SELECT INTO, REFRESH MATERIALIZED VIEW, LOCK |
| `unbounded` | UPDATE or DELETE without WHERE, TRUNCATE (along with `write`) |
| `ddl` | CREATE, ALTER, DROP, TRUNCATE, COMMENT, … |
| `admin` | roles and grants, VACUUM, ALTER SYSTEM, extensions, COPY … PROGRAM, … |
| `procedure` | CALL, DO, EXECUTE of a prepared statement |
| `session` | BEGIN, COMMIT, SET, SHOW, … |
| `other` | anything else |

PREPARE, EXPLAIN ANALYZE and DECLARE CURSOR are classified by the
statement they wrap. Examples:

- Read-only for a group (say `analysts`): deny `write, ddl, admin,
  procedure` for that group. A deny always wins, so give the restriction
  to the people it is for, rather than to `anyone` with exceptions.
- Block DELETE/UPDATE without WHERE: deny `unbounded` everywhere.
- Approval for any write in `prod`: require approval for `write` on the
  folder `prod`. The approval covers that exact statement for the grant
  window: run it again once it is approved.
- Block `DROP`: deny `ddl` with the pattern `(?i)^\s*drop\b`.

A refused statement gets a clear error in the client (SQLSTATE `42501`)
naming the policy, or the approval request to wait for.

## Running it

```toml
[dbproxy]
enabled = true
shared_secret_file = "/etc/mybastion/dbproxy-secret"   # >= 32 characters
address = "bastion.example.com:5433"                    # shown to users
allowed_networks = ["10.0.0.0/8"]                       # where databases may be
# token_minutes = 15
```

```
mybastion-dbproxy -listen :5433 -core http://127.0.0.1:8089 \
    -secret-file /etc/mybastion/dbproxy-secret \
    -tls-cert /etc/mybastion/tls/cert.pem -tls-key /etc/mybastion/tls/key.pem
```

The proxy talks to the core's internal API (`/internal/db/...`) with the
shared secret in `X-Mybastion-Proxy-Secret`; keep it on the same host or a
private network.

Build: `cd dbproxy && go build -o mybastion-dbproxy .` (Go 1.25 and a C
compiler, for the parser).

## Limits

- A function called from a SELECT can change data, and `CALL`, `DO` and
  `EXECUTE` can run anything: they are the `procedure` class, to deny or
  approve as a whole.
- Policies decide per statement; a statement refused inside a transaction
  block leaves the transaction open (the database never saw it).
- Column masking in results, and MySQL/MariaDB, come later.

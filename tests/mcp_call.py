#!/usr/bin/env python3
"""A minimal MCP client (stdlib only) for the live tests: one JSON-RPC
request to a Streamable HTTP endpoint, the result printed as JSON.

Usage: mcp_call.py URL KEY METHOD [PARAMS_JSON]

Prints {"status": <http status>, "body": <JSON-RPC response or text>}. A
`text/event-stream` answer is read for its last `data:` message.
"""

import json
import sys
import urllib.error
import urllib.request

url, key, method = sys.argv[1], sys.argv[2], sys.argv[3]
params = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
if method == "initialize":
    params = {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "mybastion-test", "version": "1"},
        **params,
    }
req = urllib.request.Request(
    url,
    data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
    headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-06-18",
        **({"Authorization": f"Bearer {key}"} if key else {}),
    },
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=60) as r:
        status, ctype, raw = r.status, r.headers.get("Content-Type", ""), r.read().decode()
        auth = r.headers.get("WWW-Authenticate")
except urllib.error.HTTPError as e:
    status, ctype, raw = e.code, e.headers.get("Content-Type", ""), e.read().decode()
    auth = e.headers.get("WWW-Authenticate")

body = raw
if "text/event-stream" in ctype:
    data = [l[5:].strip() for l in raw.splitlines() if l.startswith("data:") and l[5:].strip()]
    body = data[-1] if data else ""
try:
    body = json.loads(body)
except ValueError:
    pass
print(json.dumps({"status": status, "www_authenticate": auth, "body": body}))

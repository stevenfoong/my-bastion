#!/usr/bin/env python3
"""An MCP OAuth client and the person's browser, for tests/test_mcp_oauth.sh
(stdlib only). Prints one JSON object.

  oauth_client.py flow BASE NAME [SCOPE] [--deny] [--bad-verifier]
      Discover from /mcp's 401, register NAME, run the authorization code
      flow with PKCE through the bastion's sign-in and consent screen (the
      browser follows redirects and keeps cookies), and exchange the code.
      -> {"stage": "tokens"|"pending"|"denied"|"error", "client_id", "tokens",
          "consent", ...}
  oauth_client.py refresh BASE CLIENT_ID REFRESH_TOKEN
      -> {"status", "body"}
  oauth_client.py authorize BASE CLIENT_ID REDIRECT_URI
      An authorize request as the client might forge it -> {"status", "location"}
"""

import base64
import hashlib
import html
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REDIRECT = "http://127.0.0.1:9/cb"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


opener = urllib.request.build_opener(NoRedirect)


def http(method, url, data=None, headers=None, cookies=None):
    h = dict(headers or {})
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        r = opener.open(req, timeout=30)
    except urllib.error.HTTPError as e:
        r = e
    if cookies is not None:
        for c in r.headers.get_all("Set-Cookie") or []:
            name, _, rest = c.partition("=")
            value = rest.split(";", 1)[0]
            if "Max-Age=0" in c:
                cookies.pop(name, None)
            else:
                cookies[name] = value
    return r.status, r.headers, r.read().decode(errors="replace")


def form(d):
    return urllib.parse.urlencode(d)


def flow(base, name, scope=None, deny=False, bad_verifier=False):
    out = {}
    st, hd, _ = http("POST", base + "/mcp", "{}", {"Content-Type": "application/json"})
    m = re.search(r'resource_metadata="([^"]+)"', hd.get("WWW-Authenticate", ""))
    out["challenge"] = bool(m) and st == 401
    prm = json.loads(http("GET", m.group(1))[2])
    asm = json.loads(http("GET", prm["authorization_servers"][0] + "/.well-known/oauth-authorization-server")[2])
    st, _, b = http("POST", asm["registration_endpoint"],
                    json.dumps({"client_name": name, "redirect_uris": [REDIRECT],
                                "token_endpoint_auth_method": "none"}),
                    {"Content-Type": "application/json"})
    reg = json.loads(b)
    out["client_id"] = cid = reg["client_id"]
    verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"response_type": "code", "client_id": cid, "redirect_uri": REDIRECT, "state": "st8",
         "code_challenge": challenge, "code_challenge_method": "S256", "resource": prm["resource"]}
    if scope:
        q["scope"] = scope
    url = asm["authorization_endpoint"] + "?" + urllib.parse.urlencode(q)
    jar = {}
    for _ in range(12):
        st, hd, body = http("GET", url, cookies=jar)
        if st in (301, 302, 303, 307):
            loc = urllib.parse.urljoin(url, hd["Location"])
            if loc.startswith(REDIRECT):
                url = loc
                break
            url = loc
            continue
        break
    if not url.startswith(REDIRECT):
        if "Waiting for an admin" in body:
            out["stage"] = "pending"
            return out
        m = re.search(r'name="csrf" value="([0-9a-f]+)"', body)
        if not m:
            out.update(stage="error", status=st, page=body[:500])
            return out
        out["consent"] = html.unescape(re.sub(r"<[^>]+>", " ", body))
        st, hd, body = http("POST", base + "/oauth/authorize",
                            form({"csrf": m.group(1), "decision": "deny" if deny else "approve"}),
                            {"Content-Type": "application/x-www-form-urlencoded"}, cookies=jar)
        url = hd.get("Location", "")
    params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
    out["state_back"] = params.get("state")
    if "error" in params:
        out.update(stage="denied", error=params["error"])
        return out
    out["iss"] = params.get("iss")
    st, _, b = http("POST", asm["token_endpoint"],
                    form({"grant_type": "authorization_code", "code": params["code"], "client_id": cid,
                          "redirect_uri": REDIRECT, "resource": prm["resource"],
                          "code_verifier": verifier + ("x" if bad_verifier else "")}),
                    {"Content-Type": "application/x-www-form-urlencoded"})
    out["token_status"] = st
    out["tokens"] = json.loads(b)
    out["stage"] = "tokens" if st == 200 else "error"
    return out


args = sys.argv[1:]
if args[0] == "flow":
    pos = [a for a in args[1:] if not a.startswith("--")]
    print(json.dumps(flow(pos[0], pos[1], pos[2] if len(pos) > 2 else None,
                          "--deny" in args, "--bad-verifier" in args)))
elif args[0] == "refresh":
    st, _, b = http("POST", args[1] + "/oauth/token",
                    form({"grant_type": "refresh_token", "client_id": args[2], "refresh_token": args[3]}),
                    {"Content-Type": "application/x-www-form-urlencoded"})
    print(json.dumps({"status": st, "body": json.loads(b)}))
elif args[0] == "authorize":
    q = {"response_type": "code", "client_id": args[2], "redirect_uri": args[3],
         "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"}
    st, hd, _ = http("GET", args[1] + "/oauth/authorize?" + urllib.parse.urlencode(q))
    print(json.dumps({"status": st, "location": hd.get("Location")}))

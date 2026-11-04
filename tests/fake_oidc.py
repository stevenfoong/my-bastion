#!/usr/bin/env python3
"""A stand-in OpenID Connect provider for tests/test_mcp_oauth.sh.

Discovery, JWKS, /authorize (signs the configured user straight in), /token
(authorization_code and refresh_token, ID tokens signed RS256 with a key
made by openssl at start-up), and test hooks:

  POST /test/user    {"email", "groups", "sub"}: who signs in, and the groups
                     the next tokens carry
  POST /test/revoke  revoke every refresh token (the user left the company)
  GET  /test/calls   the grant types /token was called with

Usage: fake_oidc.py PORT CLIENT_ID WORKDIR
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, CLIENT_ID, WORK = int(sys.argv[1]), sys.argv[2], sys.argv[3]
ISSUER = f"http://127.0.0.1:{PORT}"
KEY = os.path.join(WORK, "idp-key.pem")
subprocess.run(["openssl", "genrsa", "-out", KEY, "2048"], check=True, capture_output=True)
mod_hex = subprocess.run(["openssl", "rsa", "-in", KEY, "-noout", "-modulus"],
                         check=True, capture_output=True, text=True).stdout.strip().split("=", 1)[1]


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


JWK = {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
       "n": b64u(bytes.fromhex(mod_hex)), "e": "AQAB"}

lock = threading.Lock()
user = {"email": "alice@example.com", "sub": "alice", "groups": ["ops"]}
codes, refresh_tokens, calls = {}, {}, []


def sign(claims):
    header = b64u(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "k1"}).encode())
    payload = b64u(json.dumps(claims).encode())
    msg = f"{header}.{payload}".encode()
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", KEY, "-binary"],
                         input=msg, check=True, capture_output=True).stdout
    return f"{header}.{payload}.{b64u(sig)}"


def id_token(nonce=None):
    now = int(time.time())
    c = {"iss": ISSUER, "sub": user["sub"], "aud": CLIENT_ID, "iat": now, "exp": now + 300,
         "email": user["email"], "email_verified": True, "name": "Test User",
         "groups": list(user["groups"])}
    if nonce:
        c["nonce"] = nonce
    return sign(c)


def tokens(offline, nonce=None):
    out = {"access_token": b64u(os.urandom(16)), "token_type": "Bearer", "expires_in": 300,
           "id_token": id_token(nonce)}
    if offline:
        rt = b64u(os.urandom(24))
        refresh_tokens[rt] = True
        out["refresh_token"] = rt
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/.well-known/openid-configuration":
            return self.reply({
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token",
                "jwks_uri": ISSUER + "/jwks",
                "userinfo_endpoint": ISSUER + "/userinfo",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "scopes_supported": ["openid", "email", "profile", "offline_access"],
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
            })
        if u.path == "/jwks":
            return self.reply({"keys": [JWK]})
        if u.path == "/authorize":
            code = b64u(os.urandom(16))
            with lock:
                codes[code] = {"nonce": q.get("nonce"), "offline": "offline_access" in q.get("scope", "")}
            loc = q["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": q.get("state", "")})
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()
            return
        if u.path == "/test/calls":
            with lock:
                return self.reply(calls)
        self.reply({"error": "not found"}, 404)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        raw = self.body()
        if u.path == "/token":
            f = dict(urllib.parse.parse_qsl(raw))
            with lock:
                calls.append(f.get("grant_type"))
                if f.get("grant_type") == "authorization_code":
                    c = codes.pop(f.get("code"), None)
                    if not c:
                        return self.reply({"error": "invalid_grant"}, 400)
                    return self.reply(tokens(c["offline"], c["nonce"]))
                if f.get("grant_type") == "refresh_token":
                    if not refresh_tokens.pop(f.get("refresh_token"), None):
                        return self.reply({"error": "invalid_grant", "error_description": "revoked"}, 400)
                    return self.reply(tokens(True))
            return self.reply({"error": "unsupported_grant_type"}, 400)
        if u.path == "/test/user":
            with lock:
                user.update(json.loads(raw or "{}"))
            return self.reply(user)
        if u.path == "/test/revoke":
            with lock:
                refresh_tokens.clear()
            return self.reply({"ok": True})
        self.reply({"error": "not found"}, 404)


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

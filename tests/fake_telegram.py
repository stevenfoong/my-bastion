#!/usr/bin/env python3
"""A stand-in for the Telegram Bot API, for tests/test_telegram_approval.sh.

Serves /bot<TOKEN>/<method> for the methods My Bastion calls, records every
call, and lets the test queue updates as if users sent them:

  POST /test/update   body: one Update object (update_id is filled in)
  GET  /test/calls    every recorded call: [{"method", "body"}, ...]

Usage: fake_telegram.py PORT TOKEN
"""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, TOKEN = int(sys.argv[1]), sys.argv[2]
lock = threading.Condition()
updates, calls = [], []
next_update, next_message = [1], [100]


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
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/test/calls":
            with lock:
                return self.reply(calls)
        self.reply({"ok": False}, 404)

    def do_POST(self):
        if self.path == "/test/update":
            u = self.body()
            with lock:
                u["update_id"] = next_update[0]
                next_update[0] += 1
                updates.append(u)
                lock.notify_all()
            return self.reply({"ok": True})
        prefix = "/bot" + TOKEN + "/"
        if not self.path.startswith(prefix):
            return self.reply({"ok": False, "error_code": 401, "description": "Unauthorized"}, 401)
        method, body = self.path[len(prefix):], self.body()
        with lock:
            if method != "getUpdates":
                calls.append({"method": method, "body": body})
        if method == "getMe":
            return self.reply({"ok": True, "result": {"id": 42, "is_bot": True, "username": "test_bastion_bot"}})
        if method == "getUpdates":
            offset = body.get("offset", 0)
            deadline = time.time() + min(body.get("timeout", 0), 2)
            with lock:
                while True:
                    ready = [u for u in updates if u["update_id"] >= offset]
                    if ready or time.time() >= deadline:
                        break
                    lock.wait(0.2)
            return self.reply({"ok": True, "result": ready})
        if method == "sendMessage":
            with lock:
                next_message[0] += 1
                mid = next_message[0]
            return self.reply({"ok": True, "result": {"message_id": mid, "chat": {"id": body.get("chat_id")}}})
        if method in ("editMessageText", "answerCallbackQuery"):
            return self.reply({"ok": True, "result": True})
        self.reply({"ok": False, "description": "unknown method " + method}, 400)


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

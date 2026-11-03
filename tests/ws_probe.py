#!/usr/bin/env python3
"""A minimal WebSocket client (stdlib only) for the live tests: plays a
browser on a session's Guacamole tunnel.

Usage: ws_probe.py HOST:PORT PATH HEADER SECONDS [INSTRUCTION ...]

Connects to ws://HOST:PORT/PATH with HEADER (e.g. "Authorization: Bearer x"),
waits a moment for guacd's first instructions, sends each INSTRUCTION as its
own text message, then prints every text message received for SECONDS.
"""

import base64
import os
import socket
import struct
import sys
import time

addr, path, header, seconds = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
to_send = sys.argv[5:]
host, port = addr.rsplit(":", 1)

s = socket.create_connection((host, int(port)), timeout=5)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall((
    f"GET {path} HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    f"Sec-WebSocket-Protocol: guacamole\r\n{header}\r\n\r\n"
).encode())

buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        sys.exit("connection closed during the handshake")
    buf += chunk
head, buf = buf.split(b"\r\n\r\n", 1)
if b" 101 " not in head.split(b"\r\n")[0]:
    sys.exit("handshake refused: " + head.split(b"\r\n")[0].decode())


def send(text):
    data = text.encode()
    mask = os.urandom(4)
    n = len(data)
    if n < 126:
        hdr = struct.pack("!BB", 0x81, 0x80 | n)
    elif n < 65536:
        hdr = struct.pack("!BBH", 0x81, 0x80 | 126, n)
    else:
        hdr = struct.pack("!BBQ", 0x81, 0x80 | 127, n)
    s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def frames():
    """Yield (opcode, payload) until the deadline or the socket closes."""
    global buf
    while True:
        while len(buf) < 2 or len(buf) < frame_len(buf):
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                return
            if not chunk:
                return
            buf += chunk
        n = frame_len(buf)
        op, payload = buf[0] & 0x0F, parse_payload(buf)
        buf = buf[n:]
        yield op, payload


def header_len(b):
    n = b[1] & 0x7F
    return 2 + (2 if n == 126 else 8 if n == 127 else 0)


def payload_len(b):
    n = b[1] & 0x7F
    if n == 126:
        return struct.unpack("!H", b[2:4])[0]
    if n == 127:
        return struct.unpack("!Q", b[2:10])[0]
    return n


def frame_len(b):
    if len(b) < 2 or len(b) < header_len(b):
        return 1 << 62
    return header_len(b) + payload_len(b)


def parse_payload(b):
    h = header_len(b)
    return b[h:h + payload_len(b)]


deadline = time.time() + seconds
s.settimeout(0.5)
sent = False
start = time.time()
while time.time() < deadline:
    if not sent and time.time() - start > 1.0:
        for ins in to_send:
            send(ins)
        sent = True
    got_any = False
    for op, payload in frames():
        got_any = True
        if op == 0x1:
            print(payload.decode(errors="replace"))
        elif op == 0x8:
            sys.exit(0)
        break
    if not got_any and not sent:
        continue

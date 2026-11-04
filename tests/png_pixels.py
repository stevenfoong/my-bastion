#!/usr/bin/env python3
"""Read an 8-bit RGB or RGBA PNG (stdlib only) for the live tests.

Usage: png_pixels.py FILE size            -> "W H"
       png_pixels.py FILE at X Y          -> "R G B"
       png_pixels.py FILE nonblack        -> number of pixels that are not black
"""

import struct
import sys
import zlib


def read(path):
    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    pos, idat, w, h, ctype = 8, b"", 0, 0, 0
    while pos < len(data):
        n, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + n]
        if kind == b"IHDR":
            w, h, depth, ctype = struct.unpack(">IIBB", body[:10])
            assert depth == 8 and ctype in (2, 6), "only 8-bit RGB/RGBA"
        elif kind == b"IDAT":
            idat += body
        pos += 12 + n
    bpp = 3 if ctype == 2 else 4
    raw, stride = zlib.decompress(idat), w * bpp
    rows, prev, i = [], bytearray(stride), 0
    for _ in range(h):
        f, line = raw[i], bytearray(raw[i + 1:i + 1 + stride])
        i += 1 + stride
        for x in range(stride):
            a = line[x - bpp] if x >= bpp else 0
            b = prev[x]
            c = prev[x - bpp] if x >= bpp else 0
            if f == 1:
                line[x] = (line[x] + a) & 255
            elif f == 2:
                line[x] = (line[x] + b) & 255
            elif f == 3:
                line[x] = (line[x] + (a + b) // 2) & 255
            elif f == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                line[x] = (line[x] + pr) & 255
        rows.append(line)
        prev = line
    return w, h, bpp, rows


w, h, bpp, rows = read(sys.argv[1])
cmd = sys.argv[2]
if cmd == "size":
    print(w, h)
elif cmd == "at":
    x, y = int(sys.argv[3]), int(sys.argv[4])
    print(*rows[y][x * bpp:x * bpp + 3])
elif cmd == "nonblack":
    print(sum(1 for r in rows for x in range(w) if any(r[x * bpp:x * bpp + 3])))

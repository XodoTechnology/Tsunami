#!/usr/bin/env python3
"""Announce over real I2P: ctrl socket owns session, second socket does
STREAM CONNECT, then HTTP GET /a with ip=<own destination>."""
import sys, socket, urllib.parse, time
sys.path.insert(0, "/root/i2p_test")
from samlib import Sam

TRACKER_DEST = sys.argv[1]
INFO_HASH = sys.argv[2] if len(sys.argv) > 2 else "00112233445566778899aabbccddeeff00112233"
COMPACT = sys.argv[3] if len(sys.argv) > 3 else "1"
EXTRA_HEADERS = sys.argv[4] if len(sys.argv) > 4 else ""

def http_get(sock, path, extra=b""):
    req = f"GET {path} HTTP/1.1\r\nHost: tracker\r\nConnection: close\r\n{extra}\r\n"
    sock.sendall(req.encode())
    sock.settimeout(60)
    data = b""
    try:
        while True:
            c = sock.recv(65536)
            if not c:
                break
            data += c
    except socket.timeout:
        pass
    return data

def main():
    ctrl = Sam(name="client-ctrl")
    mydest = ctrl.session_create("client", options="i2cp.leaseSetEncType=4,0")
    print(f"CLIENT_DEST={mydest}", flush=True)
    time.sleep(2)
    conn = Sam(name="client-conn")
    conn.stream_connect("client", TRACKER_DEST, port=80, timeout=300)
    print("STREAM_CREATED", flush=True)
    params = {
        "info_hash": INFO_HASH,
        "ip": mydest + ".i2p",
        "peer_id": "TUEV-i2ptest0000001"[:20],
        "port": "6881",
        "left": "12345",
        "compact": COMPACT,
        "event": "started",
        "numwant": "50",
    }
    resp = http_get(conn.sock, "/a?" + urllib.parse.urlencode(params), EXTRA_HEADERS.encode())
    print("=== RESPONSE ===")
    print(resp.decode(errors="replace")[:2000])

if __name__ == "__main__":
    main()

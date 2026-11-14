"""Minimal SAM v3.3 bridge client (HELLO handshake then text commands)."""
import socket, time

class Sam:
    def __init__(self, host="127.0.0.1", port=7656, name="tsunami-test", timeout=120):
        self.sock = socket.create_connection((host, port), timeout=15)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.name = name
        # Version negotiation first (i2pd requires HELLO before CONNECT).
        self._cmd("HELLO VERSION MIN=3.0 MAX=3.3")
        self._expect("HELLO")
        # i2pd SAM has no CONNECT registration — commands follow HELLO.

    def _cmd(self, s):
        self.sock.sendall(s.encode() + b"\n")

    def _line(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("SAM closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode(errors="replace").strip()

    def _expect(self, prefix, max_lines=80):
        for _ in range(max_lines):
            l = self._line()
            if l.startswith(prefix):
                return l
        raise TimeoutError(f"no {prefix} reply")

    def session_create(self, sid, dest="TRANSIENT", style="STREAM", options=""):
        cmd = f"SESSION CREATE STYLE={style} ID={sid} DESTINATION={dest}"
        if options:
            cmd += " " + options
        self._cmd(cmd)
        for _ in range(80):
            l = self._line()
            if l.startswith("SESSION STATUS") and ("RESULT=CREATED" in l or "RESULT=OK" in l):
                for kv in l.split():
                    if kv.startswith("DESTINATION="):
                        return kv.split("=", 1)[1]
                return ""
            if "RESULT=" in l and "CREATED" not in l and "RESULT=OK" not in l:
                raise RuntimeError(l)
        raise TimeoutError("session create")

    def session_close(self, sid):
        self._cmd(f"SESSION CLOSE ID={sid}")

    def stream_connect(self, sid, host, port=80, timeout=300):
        self._cmd(f"STREAM CONNECT ID={sid} DESTINATION={host} PORT={port}")
        for _ in range(80):
            l = self._line()
            if "STREAM_STATUS" in l and ("RESULT=STREAM_CREATED" in l or "RESULT=OK" in l):
                return
            if "RESULT=" in l and "STREAM_CREATED" not in l and "RESULT=OK" not in l:
                raise RuntimeError(l)
        raise TimeoutError("stream connect")

    def stream_accept(self, sid, timeout=600):
        self._cmd(f"STREAM ACCEPT ID={sid}")
        for _ in range(80):
            l = self._line()
            if "STREAM_STATUS" in l and ("ACCEPTED" in l or "STREAM_CREATED" in l):
                return
            if "RESULT=" in l and "ACCEPTED" not in l and "STREAM_CREATED" not in l:
                raise RuntimeError(l)
        raise TimeoutError("stream accept")

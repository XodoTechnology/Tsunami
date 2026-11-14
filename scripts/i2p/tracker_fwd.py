#!/usr/bin/env python3
"""Tracker-side I2P endpoint via SAM: control socket owns the session,
second socket issues STREAM FORWARD to the local Tsunami I2P listener."""
import sys, time
sys.path.insert(0, "/root/i2p_test")
from samlib import Sam

LOCAL_PORT = 3999

def main():
    ctrl = Sam(name="tracker-ctrl")
    dest = ctrl.session_create("tracker", options="i2cp.leaseSetEncType=4,0")
    print(f"TRACKER_DEST={dest}", flush=True)
    fwd = Sam(name="tracker-fwd")
    fwd._cmd(f"STREAM FORWARD ID=tracker PORT={LOCAL_PORT} HOST=127.0.0.1 SILENT=true")
    for _ in range(80):
        l = fwd._line()
        print("FWD>", l, flush=True)
        if "STREAM STATUS" in l:
            break
    print("forwarding I2P -> 127.0.0.1:%d" % LOCAL_PORT, flush=True)
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()

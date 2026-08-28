# Security Advisory — D-Link DIR-868L B1 `cgibin` Pre-auth Stack Overflow RCE

| Field | Value |
|---|---|
| Title | Unauthenticated stack-based buffer overflow in the `cgibin` authentication handler of D-Link DIR-868L rev. B1 leads to remote code execution as root |
| Affected vendor | D-Link |
| Affected product | DIR-868L, hardware revision B1 |
| Affected firmware | v2.01b05 (`DIR868LB1_FW201b05.bin`, build 2015-01-29) — other versions untested |
| Vulnerable component | `/htdocs/cgibin` — MD5 `64a37f67c57dc25b3678dbcc8554c10e`, SHA-256 `d09c8d79cbe2e896e78a82adfcc3fab15f804a8ee551524fe148223071392a55` |
| Vulnerable function | authentication dispatcher, file offset `0x14760` |
| Weakness | CWE-121 (stack-based buffer overflow) |
| CVSS 3.1 | **9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Attack vector | Network, **pre-authentication**, no user interaction (single HTTP GET) |
| CVE | `<pending — requested>` |

## 1. Summary

The `cgibin` multi-call CGI binary serves the mydlink / SharePort web
authentication endpoints. Its authentication dispatcher copies the URL query
parameters `id` and `password` into fixed 0x400-byte stack buffers using
`strcpy()` at function entry, before any authentication or validation logic
runs. The query-string parser feeding these copies (a grow-by-32
dynamic-string chain) imposes no length limit on parameter values.

An unauthenticated attacker sends one HTTP GET request with an oversized `id`
(or `password`) value and overwrites the saved return address on the stack:

- `id` parameter — saved frame pointer at offset `0x740`, saved return address at `0x744`
- `password` parameter — saved return address at offset `0xB44`
- login-path second copy (`sub_13CF0`, strcpys into a 392-byte stack object) — return address at parameter offset `0x198`

The web server executes CGIs as root, has no stack canary, and maps the stack
executable (`PT_GNU_STACK` flags = 6). Confirmed impact: **arbitrary command
execution as root with a single request**, independent of kernel ASLR modes
0/1.

## 2. Affected entry points

| Interface | Endpoint | Dispatch |
|---|---|---|
| LAN web UI (80/tcp) | `/authentication.cgi`, `/authentication_logout.cgi`, `/webfa_authentication.cgi`, `/webfa_authentication_logout.cgi` | basename dispatch in `cgibin` |
| SharePort WebAccess instance (8181/tcp, WAN-exposed when remote access enabled) | `/dws/api/Login`, `/dws/api/Logout` | alias → `/htdocs/web/webfa_authentication*.cgi` (per `httpcfg.php`, `webaccess_server()` rules) |

## 3. Proof of concept (crash-level)

```
GET /webfa_authentication.cgi?id=<1864-byte string ending in BBBB>&password=x HTTP/1.0
```

The CGI process receives SIGSEGV at the function epilogue
(`POP {R11,PC}`, offset `0x14CBC`). With a De Bruijn pattern as the `id`
value, the program counter is loaded from pattern offset **0x744 (1860)** —
return-address control confirmed by static analysis, Unicorn instruction-level
emulation, and qemu-user + GDB dynamic analysis.

See [poc/poc_crash.py](poc/poc_crash.py). End-to-end weaponization was verified
in a lab (FirmAE full-system emulation) and on authorized production hardware
(single request → `system()` → root command execution, `Uid: 0`, `CapEff:
ffffffffffffffff`). The ASLR-independent exploit chain will be published after
the disclosure window.

## 4. Related, distinct vulnerability

[CVE-2016-5681](https://www.kb.cert.org/vuls/id/332115) / VU#332115
(D-Link SAP10063, reported by NCC Group, 2016-08) is a stack overflow of the
session-cookie `uid` value in the cookie-validation function of the same
`dws/api/Login` endpoint on overlapping models, including DIR-868L B1.
Differences from the vulnerability documented here:

| | CVE-2016-5681 | This advisory |
|---|---|---|
| Input | HTTP `Cookie:` header, `uid=` value | URL query parameters `id` / `password` |
| Vulnerable function | session-cookie validation (`sess_get_uid`-style parser) | authentication dispatcher entry strcpys (`0x147E0` / `0x14834`) |
| Overwrite target | cookie-path copy | return address at param offsets `0x744` / `0xB44` / `0x198` |

Firmware built before the 2016 fix (e.g. v2.01b05, 2015-01) contains both
flaws. CVE-2016-5681 is actively exploited in the wild as of 2026
("AryStinger" campaign), underscoring the real-world exposure of these
endpoints.

## 5. Recommended fix

1. Replace the entry strcpys (offsets `0x147E0`, `0x14834`) and the
   login-path copies in `sub_13CF0` with bounded copies plus server-side
   length validation (legitimate credentials are ≤ 128 bytes);
2. Enforce a maximum parameter-value length in the query-string parser chain;
3. Rebuild with `-fstack-protector-strong` and `-z noexecstack` (the binary
   currently has an executable stack and no canaries).

## 6. Timeline

| Date | Event |
|---|---|
| 2026-08 | Vulnerability discovered and verified (static, emulation, qemu, FirmAE, authorized production test) |
| 2026-08-28 | D-Link PSIRT notified |
| (pending) | CVE requested |
| (pending) | Public disclosure (this repository) |
| (pending) | Weaponized exploit chain published |

## 7. Credit

Discovered and researched by `Walnut1337` (2026-08). Contact:
`walnut1337@163.com (independent security researcher)`.

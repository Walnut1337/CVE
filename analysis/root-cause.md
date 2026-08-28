# Root-Cause Analysis — cgibin Authentication Handler Stack Overflow

## Target

| Property | Value |
|---|---|
| Firmware | `DIR868LB1_FW201b05.bin` (DIR-868L rev. B1, v2.01b05, build 2015-01-29) |
| Component | `/htdocs/cgibin` — ARM EABI5 little-endian, pure ARM mode, non-PIE (base 0x8000) |
| MD5 | `64a37f67c57dc25b3678dbcc8554c10e` |
| SHA-256 | `d09c8d79cbe2e896e78a82adfcc3fab15f804a8ee551524fe148223071392a55` |
| C library | uClibc 0.9.32.1 |
| Web server | thttpd-derivative `/sbin/httpd` (URL budget ~4001 bytes) |

Mitigations absent:

| Mitigation | Status |
|---|---|
| Stack canary | ✗ none (prologue is a plain `PUSH {R11,LR}`) |
| NX | ✗ `PT_GNU_STACK` flags = 6 (RW+X, executable stack) |
| PIE | ✗ fixed base 0x8000 |
| Input length validation | ✗ none in the parser chain |
| Auth before parse | ✗ overflow happens before authentication |

## Vulnerable code path

`main` → dispatcher (basename of argv[0], offset `0x97F4`) → authentication
handler `sub_14760` (offset `0x14760`), dispatched for
`authentication.cgi`(0) / `authentication_logout.cgi`(1) /
`webfa_authentication.cgi`(2) / `webfa_authentication_logout.cgi`(3).

At function entry — before the REQUEST_METHOD check, before any session or
credential validation:

```c
s1 = getenv("REQUEST_METHOD");
dword_35468 = new_dynstr();
parse_query(0x12A74, "id");          // parses REQUEST_URI's query string
v2 = get_value(dword_35468);
strcpy(v8, v2);                      // ① 0x147E0: id  -> 0x400 stack buf @ r11-0x744
parse_query(0x12A74, "password");
v4 = get_value(dword_35468);
strcpy(v7, v4);                      // ② 0x14834: password -> 0x400 stack buf @ r11-0xB44
// ... only now: method checks, session lookup, password verification
```

A second, shorter copy exists on the login path: `sub_13CF0` (offset
`0x13CF0`) strcpys the same values into a 392-byte stack object (`r11-0x198`).

## The unbounded parser chain

| Function | Offset | Behavior |
|---|---|---|
| `sub_AB9C` | 0xAB9C | takes `REQUEST_URI`, splits at `?`, feeds chars to the parser |
| `sub_A9EC` | 0xA9EC | per-char `name=value` state machine (`&` / `=` separators); **no URL-decode** (raw byte passthrough) |
| `sub_1F244` | 0x1F244 | appends one char to a dynamic string, grows when full |
| `sub_1F168` | 0x1F168 | growth: `cap += 32; realloc(buf, cap+1)` — **no upper bound** |
| `sub_12A74` | 0x12A74 | parameter-name match callback (`strcmp(name, "id")` etc.) |
| `sub_1F300` | 0x1F300 | appends the complete value into a global list (same unbounded growth) |

## Overwrite geometry

Stack frame: `PUSH {R11,LR}; ADD R11,SP,#4; SUB SP,SP,#0xB50` (SP = R11-0xB54).
Epilogue `0x14CBC`: `SUB SP,R11,#4; POP {R11,PC}`.

| Stack object | Rel. R11 | Offset from `id` buf | Offset from `password` buf |
|---|---|---|---|
| `id` buffer v8 (0x400) | -0x744 | 0 | +0x400 |
| local `s1` pointer (REQUEST_METHOD) | -0x8 | 0x73C | — |
| saved R11 | -0x4 | **0x740** | 0xB40 |
| saved LR (return address) | 0 | **0x744** | **0xB44** |
| login-path copy in `sub_13CF0`: s1/LR from `id` value | — | 0x190 / **0x198** | — |

Local pointer slots (e.g. `s1` at 0x73C) sit **before** the return address on
the overwrite path: a naive overflow crashes in `strcmp(s1, "GET")` before the
epilogue. Working exploits must therefore either repair the pointer slots or
control them — both straightforward since their offsets are fixed.

An `id` value of exactly **1864 (0x748)** bytes overwrites through the saved
LR and stops one byte into the caller frame (harmless in practice); longer
values smash the caller's argv array, which is the natural crash boundary for
simple PoCs.

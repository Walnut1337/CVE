# D-Link DIR-868L (rev. B1) — Unauthenticated Stack Overflow RCE in `cgibin` Authentication Handler

> Pre-auth remote code execution as **root** via a single unauthenticated HTTP GET request.
> Affected: DIR-868L **B1**, firmware **v2.01b05** (`DIR868LB1_FW201b05.bin`, 2015-01 build).
> CVSS 3.1: **9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` · CWE-121

**[>> Full advisory](ADVISORY.md)** · **[>> Root-cause analysis](analysis/root-cause.md)** · **[>> Crash PoC](poc/poc_crash.py)**

## TL;DR

The multi-call CGI binary `/htdocs/cgibin` handles the mydlink / SharePort web
authentication endpoints. At the very entry of the authentication dispatcher —
**before any authentication or input validation** — the URL query parameters
`id` and `password` are copied into fixed 0x400-byte stack buffers with
`strcpy()`. The query-string parser feeding these copies imposes no length
limit. A single unauthenticated GET request overwrites the saved return address
(`id`: offset **0x744**, `password`: **0xB44**). The binary has no stack canary
and an executable stack (`PT_GNU_STACK = RWX`).

```
GET /webfa_authentication.cgi?id=<1864 bytes>&password=x HTTP/1.0
                                        ^^^^^^ return address at offset 0x744
```

Attack surface:

| Interface | Endpoint | Notes |
|---|---|---|
| LAN web UI (port 80) | `/authentication.cgi`, `/webfa_authentication.cgi` (+ logout variants) | standard dispatch by basename |
| **SharePort WAN instance (port 8181)** | **`/dws/api/Login`** | alias mapped to `webfa_authentication.cgi`; exposed to the WAN when SharePort remote access is enabled |

Verified end-to-end: arbitrary command execution as root (`Uid: 0`,
`CapEff: ffffffffffffffff`) with a **single request**, **independent of kernel
ASLR** (`randomize_va_space` 0 or 1). The full weaponized exploit chain is
described in [analysis/exploit-chain.md](analysis/exploit-chain.md) and will be
published after the coordinated-disclosure window.

## Not a duplicate of CVE-2016-5681

[CVE-2016-5681](https://www.kb.cert.org/vuls/id/332115) (VU#332115) is an
overflow of the **session-cookie `uid` value** in the cookie-validation
function of the same `dws/api/Login` endpoint on the same models. The
vulnerability documented here is in the **URL query parameters `id`/`password`
at the authentication dispatcher's entry copies** — different taint source,
different vulnerable function, different overwrite offsets. Firmware built
before the 2016 fix (such as v2.01b05, 2015-01) carries **both** flaws.

## Repository layout

```
ADVISORY.md              formal advisory (severity, affected, fix, timeline)
analysis/
  root-cause.md          code-path analysis, offsets, mitigations absent
  verification.md        5-level verification methodology and evidence
  exploit-chain.md       post-disclosure: full weaponized chain (ASLR-independent)
poc/
  poc_crash.py           minimal crash PoC (return-address control demonstrator)
  firmware_hashes.txt    precise component fingerprints
```

## Responsible disclosure

Reported to D-Link PSIRT. Public weaponized exploit follows vendor fix or the
end of the coordination window, whichever comes first. See [ADVISORY.md](ADVISORY.md).

## Credit

Discovered and researched by **`Walnut1337`**, 2026-08.

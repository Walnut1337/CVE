# Verification Methodology & Evidence

Five independent verification levels, all consistent (offsets `0x740`/`0x744`
confirmed by three of them):

## 1. Static analysis (IDA)

Stack-frame derivation → saved R11 at param offset 0x740, saved LR at 0x744;
parser chain functions decompiled (no length bound anywhere); `PT_GNU_STACK`
segment flags = 6 (executable stack).

## 2. Instruction-level emulation (Unicorn)

The real `cgibin` ELF loaded into Unicorn with the PLT imports (getenv /
malloc / realloc / strcpy / strcmp / puts / …) emulated in Python; execution
starts at `sub_14760`.

- Baseline (`id=admin&password=1234`): clean return, identical output to a
  real device: `HTTP/1.1 200 OK … {"RESULT": "FAIL", "REASON": "NO_REQ_METHOD"}`
- Overflow (`id` = 2200-byte unique pattern): fetch fault at `0x41414866`
  after the epilogue `POP {R11,PC}` — pattern decodes to offset **0x744**,
  R11 from **0x740**.

## 3. qemu-user + GDB (real code, real uClibc)

```
$ env REQUEST_METHOD=BOGUS REQUEST_URI="/authentication.cgi?id=<2200 A's>&password=x" \
      REMOTE_ADDR=10.0.0.99 qemu-arm -L squashfs-root ./authentication.cgi
qemu: uncaught target signal 11 (Segmentation fault) — exit 139
```

GDB at `0x147E4` (after the first strcpy) with a De Bruijn `id`:

```
saved R11 @r11-4: 0x61616168      saved LR @r11+0: 0x6a616161
cyclic_find → 1856 (0x740) / 1860 (0x744)      # matches static + Unicorn
```

With the clobbered `s1` pointer repaired and the epilogue single-stepped:
`PC = 0x42424242` — **direct proof of return-address control**.

## 4. Full-system emulation (FirmAE)

Environment facts measured on the emulated device:

- URL length budget: ~4001 bytes (binary-searched) — exploit fits
- marker overflow (PC=0x41414141): HTTP 500 (CGI stdout is fully buffered;
  the overflow path dies at the epilogue before any flush — a 500 is the
  expected signature, not a network probe)
- `[stack] beb2f000-beb50000` → TASK_SIZE 0xC0000000, stack randomization
  window ≈ 32 MB with `randomize_va_space=1`
- ASLR off: stack-spray exploit (`exploit_pwn.py`-class) hit on the **first
  request** (candidate 0xbffff111)
- ASLR on: heap-based single-shot chain (see [exploit-chain.md](exploit-chain.md))
  hit deterministically; timing oracle (`--probe`, command = `sleep 30`) held
  the connection for exactly 31 s — command execution proof without any
  outbound connection

## 5. Authorized production hardware

- Differential fingerprint matched the reference firmware byte-for-byte
  (`/logininfo.xml` md5 `953c40de8f941e8d`, cgibin JSON response
  `{"RESULT":"FAIL","REASON":"ERR_TIMEOUT_OR_BADUID"}` = resp 6 of the same
  build, URL budget 4001)
- Entry point: SharePort WAN instance, `http://<target>:8181/dws/api/Login`
- Single-request timing probe: connection held exactly 31 s (sleep executed)
- Command output exfiltration via the CGI stdout pipe: full 21 KB
  `iptables -L -n -v` dump returned
- `/proc/self/status` of the injected command: **`Uid: 0 0 0 0`,
  `CapEff: ffffffffffffffff`** — root with all capabilities

Two platform quirks documented along the way (useful for similar targets):

1. CGI stdout only reaches the client when the output contains a blank line
   (`\n\n`) — otherwise the httpd returns 500 and discards the body;
2. only stdout flows back; stderr is dropped (a silently-successful command
   also looks like a 500).

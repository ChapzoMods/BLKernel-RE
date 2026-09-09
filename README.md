# BLKernel RE — Zero-Day Research Report

Full static reverse engineering of `BLKernel.exe` (sha256 `7d15f22e5e841d80372cd757c37a105d892389e068e2a4698a87e7f858cd902d`), led by **ChapzoMods / BL Cyber**.

**RESULT: FULLY BROKEN.** Universal keygen built from static analysis only — no debugger, no runtime patching, no binary modification.

---

## 1. Binary overview

| Property | Value |
|---|---|
| Type | PE32+ x64 console, MSVC, `requireAdministrator` |
| Size | 165,376 bytes |
| Mitigations | ASLR, DEP, HighEntropyVA (**no GuardCF**) |
| Custom sections | `.blkcode` (7,392 B encrypted, entropy 7.887), `.fptable` |
| Runtime | Custom **158-opcode bytecode VM**, hidden thread, anti-debug suite |

## 2. Protection architecture

```
main()
 ├─ AddVectoredExceptionHandler(kill-on-any-exception in module)
 ├─ CRC32(.text on disk)  ──► seed  [sub_140002B30]
 ├─ CRC32(.text in memory)──► anti-patch compare
 ├─ anti-VM/anti-debug suite (CPUID, registry, windows, MAC, timing)
 ├─ decrypt .blkcode (splitmix64 keystream, seed-derived)
 └─ NtCreateThreadEx(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER) → VM interpreter
```

VM context: 16 registers behind a **rotating permutation table**, 4-flag register (ZF/SF/CF/OF), rolling execution state, 200M instruction budget, Crockford-base32 I/O, native services (print/readline/tamper/integrity/timing/CRC).

## 3. Validation algorithm (recovered from decrypted bytecode)

1. **Gates**: tamper==0, env≤3, integrity==0, CRC checks (disk `.text`, bytecode plain+cipher), timing anti-VM (2×30s), `GETSTATE != 0`.
2. **Serial**: 16 symbols, Crockford base32 (`23456789ABCDEFGHJKLMNPQRSTUVWXYZ`), `-` separators → **13 payload symbols (64-bit P)** + **3 checksum symbols (15 bits)**.
3. **H** = FNV-1a-64(username) mixed with `rol(len*GOLDEN,23)` + splitmix.
4. **K** = 16-round key schedule (constants = fractional hex digits of π).
5. **Verifier** `r8 = V(P,H,K)`: splitmix + 7 rounds of (SBOX → +K → splitmix → ^π → rol) + final whitening triple.
6. `r8` keys a splitmix64 keystream that decrypts a 512-byte blob → must start with **`"BLK!"`** and satisfy an internal **hash chain**.

## 4. Zero-days / vulnerabilities found

### BLK-RE-001 — Offline decryption of the protected section (Critical)
The `.blkcode` key is `splitmix(CRC32(.text-on-disk))` — **fully derivable from the file itself**. The container (`BLKVMC01`) is decrypted 100% statically (see `poc/extract.py`). All subsequent "protection" logic is exposed.

### BLK-RE-002 — No username binding to the encrypted blob (Critical → universal keygen)
`r8_true` is a **global constant** baked into the shipped blob: it does **not** depend on the username. Since `V(P,·,K)` is a **bijection** in `P` for any fixed user, once `r8_true` is recovered, a valid `P` (and therefore a valid serial) exists **for every possible username**. Keygen: `poc/keygen_stage2.py`.

### BLK-RE-003 — Known-plaintext recovery of `r8_true` in 2^32 (Critical)
The decrypted blob must start with `"BLK!"` (32 known bits) and is printed as **printable ASCII**. Inverting splitmix64 over 2^32 candidate first words recovers `r8_true = 0x6b1f2a9d3c7e45b8` as the **unique** chain-valid solution in **49 s** single-threaded (`poc/keygen_stage1.c`). No brute force of the 2^64 space is ever needed.

### BLK-RE-004 — Anti-tamper is self-keyed (High)
Integrity = unkeyed CRC32 of `.text`. An attacker who patches the binary can simply **re-encrypt `.blkcode` with the new CRC-derived seed** (format fully known after BLK-RE-001). The tamper checks inside the VM (native services 4/13/14/15) verify against constants that the attacker can recompute.

### BLK-RE-005 — Mode-selection logic flaw (Medium)
Interactive vs `--check` mode is selected by the **environment-suspicion counter == 1**, not by the actual argument flag. Consequences:
- On physical hardware with a stealth hypervisor present (env count 1), interactive mode **never prompts** and validates empty strings.
- `--check` on bare metal (env count 0) prompts on the console instead of consuming `argv[2..3]`.

### BLK-RE-006 — TOCTOU between watchdog thread and VM checks (Medium)
`sub_140002620`-derived counters (`[0x140025B28]`, `[0x140025B24]`) are updated by a background watchdog thread while the VM reads them via native services without a consistent snapshot → race windows can flip verdicts between the two gate passes.

### BLK-RE-007 — Rolling-state anti-emulation is ineffective (Low)
`GETSTATE != 0` at `0x6E4` depends only on the deterministic instruction trace (opcode + next-PC + 31×prev). Any faithful emulator (incl. ours) satisfies it; it adds no real cost and is not input-dependent enough to be a check.

### BLK-RE-008 — Missing GuardCF (Low)
No `IMAGE_DLLCHARACTERISTICS_GUARD_CF`. Combined with the interpreter's indirect dispatch via jump tables, this widens exploitation primitives if any future memory-safety bug in the opcode handlers is found (all current handlers are bounds-checked).

## 5. Proof of Concept — universal keygen

```
r8_true = 0x6b1f2a9d3c7e45b8     # recovered offline in 49s, unique solution

user            serial (valid)
ChapzoMods      WWER-UR58-VX4J-BRDB
BL Cyber        4ACE-HUV7-SGS3-8YMW
x64dbg_fan      7FRV-QG22-8V9G-A9NL
A               DZ5S-ARFA-37AC-7JPD
```

Decrypted payload (printed on success):

```
==================================================
 BLKernel - ACCESS GRANTED
==================================================

Correct name and serial accepted.
You defeated a 156-opcode virtual machine, a chained
cipher cascade, kernel-state introspection and full
anti-analysis coverage. Respect.

FLAG: BLK{9f14c2a7e5b03d687aa1f4e92c5b8d67}
```

## 6. Reproduce

- **Static (any OS):** `pip install pefile` → `python poc/extract.py BLKernel.exe out && python poc/keygen_stage2.py <user>`
- **Full CI validation on real Windows:** GitHub Action `.github/workflows/dynamic-poc.yml` — recovers `r8_true`, forges a serial, runs the **real binary** with `--check` and asserts `exit code 0` + `ACCESS GRANTED`.

## 7. Remediation recommendations

1. Bind the blob key to `H` (username-derived): require `V(P,H,K)` to decrypt blob-specific to `H`.
2. Replace CRC32 self-checks with keyed MAC (e.g. HMAC-SHA256 with per-build random key stored server-side) and verify remotely.
3. Do not ship the encrypted verdict blob with only 96 bits of verifiable structure; add per-user nonce to the keystream.
4. Fix mode selection: use the actual `--check` flag for input routing, not the env counter.
5. Snapshot env counters atomically inside the VM services; enable `/guard:cf`.

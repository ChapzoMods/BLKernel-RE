#!/usr/bin/env python3
"""BLKernel keygen stage 2: forge a valid serial for ANY user.
   Exploits: user-hash is independent of the blob; the verifier map
   P -> r8 is a bijection for fixed (H,K). With r8_true recovered
   from the blob (stage 1), P = verifier^-1(H,K,r8_true) yields a
   valid serial for any username chosen by the attacker."""
import struct, sys
sys.path.insert(0, ".")
from vm_emul import splitmix, inv_splitmix, rol, gen_sbox, run_crackme, M64, GOLDEN

SBOX, SBOX_INV = gen_sbox()
ALPHA = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"   # char table: digits + letters minus I,O

R8_TRUE = 0x6b1f2a9d3c7e45b8

# key schedule constants (from bytecode 0x28b-0x41a) - fractional pi digits
PI = [0x4d347368c29d4e31, 0x8a2b5c1e7f3093a6, 0x1e9c3b57a62d748f,
      0x6f5a19d83c40b712, 0x9c0b73a4d51e8f26, 0x238c9e1b5d0f7a34,
      0xe7b6218f9a3c50d4, 0xb439a75e18c2f6d0, 0x5d8f23a1c90e4b76,
      0x30c1b9e4a75826fd, 0xa64e830d59c1f2b8, 0x8e9a4c0d3b7216f5,
      0x17d2e8a5f30c4b69, 0xc5a31f0d82e6749b, 0xf08b4d6c92a135e7,
      0x63b19a0e7c4f5d82]
# verifier round constants = hex digits of pi fraction, rotations 11,19,29,37,43,53,61
ROUNDS = [(0x13198a2e03707344, 11), (0xa4093822299f31d0, 19), (0x082efa98ec4e6c89, 29),
          (0x452821e638d01377, 37), (0xbe5466cf34e90c6c, 43), (0xc0ac29b7c97c50dd, 53),
          (0x3f84d5b5b5470917, 61)]
PI_HEAD = 0x243f6a8885a308d3

def ror(x, n): n &= 63; return ((x >> n) | (x << (64 - n))) & M64 if n else x

def sbox_apply(x, tbl):
    res = 0
    for i in range(8):
        res |= tbl[(x >> (8*i)) & 0xff] << (8*i)
    return res

def user_hash(user: bytes):
    FNV_BASIS = 0xcbf29ce484222325
    FNV_PRIME = 0x100000001b3
    h = FNV_BASIS
    n = len(user)                    # strlen semantics (max 64)
    h = ((h ^ n) * FNV_PRIME) & M64
    for ch in user[:64]:
        if ch == 0: break
        h = ((h ^ ch) * FNV_PRIME) & M64
    h = splitmix(h)
    h ^= rol((n * GOLDEN) & M64, 23)
    h = splitmix(h)
    return h

def key_schedule(h):
    k = h
    for c in PI:
        k = (k + rol((k ^ c) & M64, 9)) & M64
    return k

def verifier_forward(P, H, K):
    x = (P ^ rol(H, 17)) & M64
    x = splitmix(x)
    x ^= K
    x ^= PI_HEAD          # tamper flags == 0
    x = rol(x, 5)
    for c, rot in ROUNDS:
        x = sbox_apply(x, SBOX)
        x = (x + K) & M64
        x = splitmix(x)
        x ^= c
        x = rol(x, rot)
    # final whitening triple (bytecode 0x5f1-0x5f6)
    x = sbox_apply(x, SBOX)
    x = (x + K) & M64
    x = splitmix(x)
    return x ^ splitmix((K ^ 0xff00ff00ff00ff00) & M64)

def verifier_inverse(r8, H, K):
    x = (r8 ^ splitmix((K ^ 0xff00ff00ff00ff00) & M64)) & M64
    # undo final whitening triple
    x = inv_splitmix(x)
    x = (x - K) & M64
    x = sbox_apply(x, SBOX_INV)
    for c, rot in reversed(ROUNDS):
        x = ror(x, rot)
        x ^= c
        x = inv_splitmix(x)
        x = (x - K) & M64
        x = sbox_apply(x, SBOX_INV)
    x = ror(x, 5)
    x ^= PI_HEAD
    x ^= K
    x = inv_splitmix(x)
    return (x ^ rol(H, 17)) & M64

def checksum_symbols(H, P):
    z = splitmix((rol(H, 41) ^ P ^ rol(P, 19)) & M64)
    return z & 31, (z >> 5) & 31, (z >> 10) & 31

def make_serial(user: bytes):
    H = user_hash(user)
    K = key_schedule(H)
    P = verifier_inverse(R8_TRUE, H, K)
    # sanity: forward must reproduce r8
    assert verifier_forward(P, H, K) == R8_TRUE, "forward check failed"
    v12 = (P >> 60) & 15
    assert v12 < 16
    syms = [(P >> (5*i)) & 31 for i in range(12)] + [v12]
    s13, s14, s15 = checksum_symbols(H, P)
    syms += [s13, s14, s15]
    chars = [ALPHA[v] for v in syms]
    serial = "-".join("".join(chars[i:i+4]) for i in range(0, 16, 4))
    return serial, H, K, P

if __name__ == "__main__":
    user = sys.argv[1].encode() if len(sys.argv) > 1 else b"ChapzoMods"
    if len(sys.argv) > 2:
        R8_TRUE = int(sys.argv[2], 0)
    serial, H, K, P = make_serial(user)
    print(f"user   : {user.decode()}")
    print(f"H      : 0x{H:016x}")
    print(f"K      : 0x{K:016x}")
    print(f"P      : 0x{P:016x}")
    print(f"serial : {serial}")
    print()
    code, vm = run_crackme(user, serial.encode())
    print(f"[emulator] exit byte = {code} -> process exit code {2 if code else 0}")
    for o in vm.out:
        printable = o.decode(errors="replace")
        print("[emulator] output:")
        print(printable)

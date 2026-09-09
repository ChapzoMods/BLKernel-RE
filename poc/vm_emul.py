#!/usr/bin/env python3
"""BLKernel VM emulator - full faithful implementation of the recovered ISA.
Native services emulated in benign mode (no tamper, clean env, fast timing)."""
import struct, sys

M64 = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15

def splitmix(x):
    x &= M64; x ^= x >> 30; x = (x * 0xBF58476D1CE4E5B9) & M64
    x ^= x >> 27; x = (x * 0x94D049BB133111EB) & M64
    x ^= x >> 31
    return x

def inv_splitmix(y):
    M1_INV = pow(0xBF58476D1CE4E5B9, -1, 1 << 64)
    M2_INV = pow(0x94D049BB133111EB, -1, 1 << 64)
    def unsr(x, s):
        res = x
        for _ in range(64 // s + 1):
            res = x ^ (res >> s)
        return res & M64
    x = unsr(y, 31)
    x = (x * M2_INV) & M64
    x = unsr(x, 27)
    x = (x * M1_INV) & M64
    x = unsr(x, 30)
    return x

def rol(x, n): n &= 63; return ((x << n) | (x >> (64 - n))) & M64 if n else x
def sx32(v): return v - 0x100000000 if v & 0x80000000 else v
def crc_raw(data, init=0):
    crc = init
    for b in data:
        v = b ^ crc
        for _ in range(8):
            lsb = v & 1; v >>= 1
            if lsb: v ^= 0xEDB88320
        crc = v
    return crc & 0xFFFFFFFF

def gen_sbox():
    state = 0x424C4B5F53454544  # "BLK_SEED"
    sbox = list(range(256))
    for i in range(255, 0, -1):
        state ^= (state << 13) & M64
        state ^= state >> 7
        state ^= (state << 17) & M64
        state &= M64
        j = state % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return bytes(sbox), bytes(inv)

CLASS_LEN = {0:1, 1:2, 2:3, 3:6, 4:10, 5:6, 6:7, 7:5, 8:5}

class VMError(Exception): pass

class VM:
    def __init__(self, bytecode, data, memsize=0x20000, check_mode=True,
                 user=b"", serial=b"", disk_crc=0, expected=None, verbose=False):
        self.bc = bytecode
        self.mem = bytearray(memsize)
        self.mem[0:len(data)] = data
        sbox, sbinv = gen_sbox()
        self.mem[0x300:0x400] = sbox
        self.mem[0x400:0x500] = sbinv
        self.verbose = verbose
        self.disk_crc = disk_crc
        self.expected = expected or {}   # dict with 508/510 values
        if check_mode:
            u = user[:63]; s = serial[:63]
            self.mem[0:len(u)] = u
            self.mem[0x100:0x100+len(s)] = s
        self.regs = [0]*16
        self.perm = list(range(16))
        self.flags = 0
        self.pc = 0
        self.state = 0
        self.icount = 0
        self.halt = False
        self.exit_byte = 0
        self.out = []
        self.tamper = 0
        self.envcount = 1     # benign: hypervisor-only (GitHub-Actions-like)
        self.timing_ms = 12   # benign baseline
        self.clock_ms = 1000
        self.integrity = 0

    def r(self, i): return self.regs[self.perm[i & 0xf]]
    def w(self, i, v): self.regs[self.perm[i & 0xf]] = v & M64
    def setf_add(self, a, b, res):
        f = 0
        if res & M64 == 0: f |= 1
        if res & (1 << 63): f |= 2
        if res > M64: f |= 4
        if ((a ^ res) & (b ^ res)) >> 63 & 1: f |= 8
        self.flags = f
        return f
    def check_mem(self, off, size):
        if off + size > len(self.mem) or off < 0: raise VMError("mem OOB")

    def native(self, sid):
        a0 = self.regs[self.perm[0]]; a1 = self.regs[self.perm[1]]
        if sid == 0:      # EXIT_REPORT
            self.exit_byte = a0 & 0xff
            self.halt = True
        elif sid == 1:    # PRINT
            self.check_mem(a0, a1)
            self.out.append(bytes(self.mem[a0:a0+a1]))
        elif sid == 2:    # READLINE (emulated: no input available)
            n = min(a1, 0xff) if a1 else 0xff
            self.check_mem(a0, n)
            self.mem[a0] = 0
            self.w(0, 0)
        elif sid == 3:
            self.w(0, self.tamper)
        elif sid == 4:
            self.w(0, self.integrity)
        elif sid == 5:
            self.w(0, self.timing_ms)
            self.clock_ms += self.timing_ms
        elif sid == 6:
            self.w(0, self.clock_ms); self.clock_ms += 1
        elif sid == 7:
            pass
        elif sid == 11:
            self.envcount = max(self.envcount, 1)
            self.w(0, self.envcount)
        elif sid == 12:
            self.w(0, self.envcount)
        elif sid == 13:
            self.w(0, self.expected.get(510, 0))
        elif sid == 14:
            self.w(0, self.expected.get(508, 0))
        elif sid == 15:
            self.w(0, self.disk_crc)
        else:
            raise VMError(f"invalid native service {sid}")

    def step(self):
        if self.icount >= 0xbebc200: raise VMError("instruction budget exceeded")
        if self.pc + 1 > len(self.bc): raise VMError("PC OOB")
        op = self.bc[self.pc]
        if op >= 0x9e: raise VMError(f"bad opcode {op:#x} at {self.pc:#x}")
        cls = CLASS_LEN.get(self.classof(op))
        if cls is None: raise VMError(f"unknown class opcode {op:#x}")
        ln = cls
        raw = self.bc[self.pc:self.pc+ln]
        if len(raw) < ln: raise VMError("truncated instr")
        b = raw[1] if ln >= 2 else 0
        c = raw[2] if ln >= 3 else 0
        v32 = struct.unpack_from("<I", raw, 2)[0] if ln >= 6 else 0
        v32b = struct.unpack_from("<I", raw, 3)[0] if ln == 7 else 0
        v32c = struct.unpack_from("<I", raw, 1)[0] if ln == 5 else 0
        next_pc = self.pc + ln

        self.state = (self.state * 31 + op + (next_pc & 0xff)) & M64
        self.pc = next_pc
        self.icount += 1

        if op == 0x00: pass
        elif op == 0x01:
            self.halt = True; self.exit_byte = self.r(0) & 0xff
        elif op == 0x06: self.w(b, self.state)
        elif op == 0x0a: self.native(v32c)
        elif op == 0x0c: self.w(b, struct.unpack_from("<Q", raw, 2)[0])
        elif op == 0x0d: self.w(b, sx32(v32) & M64)
        elif op == 0x0e: self.w(b, self.r(c))
        elif op == 0x10:
            self.check_mem(v32, 8); self.w(b, struct.unpack_from("<Q", self.mem, v32)[0])
        elif op == 0x16:
            self.check_mem(v32, 4); self.w(b, struct.unpack_from("<I", self.mem, v32)[0])
        elif op == 0x1b:
            base = self.r(c); off = (base + sx32(v32b)) & M64
            self.check_mem(off, 8); self.w(b, struct.unpack_from("<Q", self.mem, off)[0])
        elif op == 0x1c:
            base = self.r(b); off = (base + sx32(v32b)) & M64
            self.check_mem(off, 8)
            struct.pack_into("<Q", self.mem, off, self.r(c))
        elif op == 0x1d:
            base = self.r(c); off = (base + sx32(v32b)) & M64
            self.check_mem(off, 1); self.w(b, self.mem[off])
        elif op == 0x1e:
            base = self.r(b); off = (base + sx32(v32b)) & M64
            self.check_mem(off, 1); self.mem[off] = self.r(c) & 0xff
        elif op == 0x31:
            a, bb = self.r(b), self.r(c); res = a + bb
            self.setf_add(a, bb, res); self.w(b, res)
        elif op == 0x33:
            a, bb = self.r(b), self.r(c); res = (a - bb) & M64
            f = 0
            if res == 0: f |= 1
            if res >> 63: f |= 2
            if a < bb: f |= 4
            if ((a ^ res) & (~bb ^ res)) >> 63 & 1: f |= 8
            self.flags = f; self.w(b, res)
        elif op == 0x35:
            a, bb = self.r(b), self.r(c); res = (a * bb) & M64
            f = 0
            if res == 0: f |= 1
            if res >> 63: f |= 2
            self.flags = f; self.w(b, res)
        elif op == 0x39:
            a = self.r(b); res = (a * sx32(v32)) & M64
            f = 0
            if res == 0: f |= 1
            if res >> 63: f |= 2
            self.flags = f; self.w(b, res)
        elif op == 0x3c:
            a = self.r(b); res = a + 1
            self.setf_add(a, 1, res & M64); self.w(b, res)
        elif op == 0x3f:
            a = self.r(b); bb = sx32(v32) & M64; res = (a + bb) & M64
            self.setf_add(a, bb, res); self.w(b, res)
        elif op == 0x40:
            a = self.r(b); bb = sx32(v32) & M64; res = (a - bb) & M64
            f = 0
            if res == 0: f |= 1
            if res >> 63: f |= 2
            if a < bb: f |= 4
            self.flags = f; self.w(b, res)
        elif op == 0x42:
            res = self.r(b) | self.r(c)
            f = 0
            if res == 0: f |= 1
            if res >> 63: f |= 2
            self.flags = f; self.w(b, res)
        elif op == 0x43:
            res = self.r(b) ^ self.r(c)
            f = 0
            if res == 0: f |= 1
            if res >> 63: f |= 2
            self.flags = f; self.w(b, res)
        elif op == 0x45:
            a = self.r(b); bb = sx32(v32) & M64; res = a ^ bb
            f = 0
            if a == bb: f |= 1
            if res >> 63: f |= 2
            self.flags = f; self.w(b, res)
        elif op == 0x46:
            res = self.r(b) & (sx32(v32) & M64)
            f = 0
            if res == 0: f |= 1
            if res >> 63: f |= 2
            self.flags = f; self.w(b, res)
        elif op == 0x48:
            a, bb = self.r(b), self.r(c); sh = bb & 0x3f
            res = (a << sh) & M64 if sh else a
            f = 0
            if res == 0: f |= 1
            if res >> 63: f |= 2
            if sh: 
                if (a >> (64 - sh)) & 1: f |= 4
            self.flags = f; self.w(b, res)
        elif op == 0x4e:
            a = self.r(b); sh = sx32(v32) & 0x3f
            res = a >> sh if sh else a
            f = 0
            if res == 0: f |= 1
            if res >> 63: f |= 2
            if sh and (a >> (sh - 1)) & 1: f |= 4
            self.flags = f; self.w(b, res)
        elif op == 0x50:
            a = self.r(b); sh = sx32(v32) & 0x3f
            res = rol(a, sh)
            f = 0
            if res == 0: f |= 1
            if res >> 63: f |= 2
            if res & 1: f |= 4
            self.flags = f; self.w(b, res)
        elif op == 0x57:
            a, bb = self.r(b), self.r(c)
            f = 0
            if a == bb: f |= 1
            if (a - bb) & M64 and ((a - bb) & M64) >> 63: f |= 2
            if a < bb: f |= 4
            self.flags = f
        elif op == 0x58:
            a = self.r(b); bb = sx32(v32) & M64
            f = 0
            if a == bb: f |= 1
            res = (a - bb) & M64
            if res >> 63: f |= 2
            if a < bb: f |= 4
            self.flags = f
        elif op == 0x66:
            if self.flags & 1: self.pc = (self.pc + sx32(v32c)) & M64
        elif op == 0x67:
            if not self.flags & 1: self.pc = (self.pc + sx32(v32c)) & M64
        elif op == 0x72:
            if self.flags & 4: self.pc = (self.pc + sx32(v32c)) & M64
        elif op == 0x74:
            if not self.flags & 5: self.pc = (self.pc + sx32(v32c)) & M64
        elif op == 0x75:
            if not self.flags & 4: self.pc = (self.pc + sx32(v32c)) & M64
        elif op == 0x7b:
            t = self.perm[15]
            self.regs[t] = (self.regs[t] - 1) & M64
            if self.regs[t] != 0: self.pc = (self.pc + sx32(v32c)) & M64
        elif op == 0x8b:
            dst = self.regs[self.perm[0]]; val = self.regs[self.perm[1]] & 0xff
            self.check_mem(dst, v32c)
            for i in range(v32c): self.mem[dst+i] = val
        elif op == 0x8d:
            dst = self.regs[self.perm[0]]
            self.check_mem(dst, v32c)
            for i in range(v32c): self.mem[dst+i] = 0
        elif op == 0x8e:
            a = self.r(b)
            res = 0
            for i in range(8):
                res |= self.mem[0x300 + ((a >> (8*i)) & 0xff)] << (8*i)
            self.w(b, res)
        elif op == 0x92:
            self.w(b, splitmix(self.r(b)))
        else:
            raise VMError(f"unimplemented opcode {op:#x}")

    def classof(self, op):
        # opcode class table extracted from 0x14001a690
        return CLS_TBL[op]

    def run(self):
        while not self.halt:
            self.step()
        return self.exit_byte

# class table: reconstruct from binary
import pefile
pe = pefile.PE("BLKernel.exe")
BASE = pe.OPTIONAL_HEADER.ImageBase
mem_img = pe.get_memory_mapped_image()
CLS_TBL = list(mem_img[0x14001a690-BASE:0x14001a690-BASE+0x9e])

def run_crackme(user, serial, verbose=False):
    bc = open("vm_bytecode.bin", "rb").read()
    data = open("vm_data.bin", "rb").read()
    raw = open("BLKernel.exe", "rb").read()
    disk_crc = None
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == b".text":
            disk_crc = crc_raw(raw[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData])
    expected = {508: 0xf20c403c, 510: 0x31917c11}
    vm = VM(bc, data, check_mode=True, user=user, serial=serial,
            disk_crc=disk_crc, expected=expected, verbose=verbose)
    code = vm.run()
    return code, vm

if __name__ == "__main__":
    u = sys.argv[1].encode() if len(sys.argv) > 1 else b"test"
    s = sys.argv[2].encode() if len(sys.argv) > 2 else b"2222222222222222"
    code, vm = run_crackme(u, s)
    print(f"exit byte = {code} (process exit {2 if code else 0})")
    for o in vm.out:
        print("OUT:", o)
    if vm.verbose:
        print("regs:", [hex(x) for x in vm.regs])

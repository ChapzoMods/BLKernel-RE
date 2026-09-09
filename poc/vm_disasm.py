#!/usr/bin/env python3
"""BLKernel VM bytecode disassembler - reconstructed ISA."""
import struct, sys

bc = open("/home/z/my-project/re_workspace/vm_bytecode.bin", "rb").read()

CLASS_LEN = {0:1, 1:2, 2:3, 3:6, 4:10, 5:6, 6:7, 7:5, 8:5}

# opcode semantics (only opcodes present in this bytecode + a few extra known)
NAMES = {
    0x00: ("NOP", 0), 0x01: ("HALT", 0), 0x02: ("YIELD", 0),
    0x06: ("GETSTATE", 1), 0x0a: ("NATIVE", 8), 0x0c: ("LDI64", 4),
    0x0d: ("LDI32", 3), 0x0e: ("MOV", 2), 0x10: ("LD64A", 5),
    0x16: ("LD32A", 5), 0x1b: ("LD64R", 6), 0x1c: ("ST64R", 6),
    0x1d: ("LDZ8R", 6), 0x1e: ("ST8R", 6), 0x31: ("ADD", 2), 0x33: ("SUB", 2),
    0x35: ("MUL", 2), 0x39: ("MULI", 3), 0x3c: ("INC", 1), 0x3f: ("ADDI", 3),
    0x40: ("SUBI", 3), 0x42: ("OR", 2), 0x43: ("XOR", 2), 0x45: ("XORI", 3),
    0x46: ("ANDI", 3), 0x48: ("SHL", 2), 0x4e: ("SHRI", 3), 0x50: ("ROLI", 3),
    0x57: ("CMP", 2), 0x58: ("CMPI", 3), 0x66: ("JE", 7), 0x67: ("JNE", 7),
    0x72: ("JC", 7), 0x74: ("JA", 7), 0x75: ("JAE", 7), 0x7b: ("LOOP", 7),
    0x8b: ("FILL", 8), 0x8d: ("ZERO", 8), 0x8e: ("SBOX", 1), 0x92: ("PRNG", 1),
}
NATIVE = {0:"EXIT_REPORT", 1:"PRINT", 2:"READLINE", 3:"TAMPER_FLAGS", 4:"INTEGRITY",
          5:"TIMING_BASELINE", 6:"CLOCK_MS", 7:"FLUSH", 11:"ENV_THENCOUNT",
          12:"ENV_COUNT", 13:"CRC_BYTECODE_GLOBAL", 14:"CRC_BYTECODE_CTX", 15:"DISK_CRC"}

def sx32(v): return v - 0x100000000 if v & 0x80000000 else v

def decode(pc):
    op = bc[pc]
    if op not in NAMES: return None
    name, cls = NAMES[op]
    ln = CLASS_LEN[cls]
    raw = bc[pc:pc+ln]
    args = raw[1:]
    txt = ""
    if cls == 0: txt = ""
    elif cls == 1: txt = f"r{args[0]&0xf}"
    elif cls == 2: txt = f"r{args[0]&0xf}, r{args[1]&0xf}"
    elif cls == 3:
        v = struct.unpack_from("<I", raw, 2)[0]
        txt = f"r{args[0]&0xf}, {sx32(v)}" + (f" (0x{v:x})" if sx32(v) != v else "")
    elif cls == 4:
        v = struct.unpack_from("<Q", raw, 2)[0]
        txt = f"r{args[0]&0xf}, 0x{v:016x}"
    elif cls == 5:
        v = struct.unpack_from("<I", raw, 2)[0]
        txt = f"r{args[0]&0xf}, 0x{v:x}"
    elif cls == 6:
        v = struct.unpack_from("<I", raw, 3)[0]
        txt = f"r{args[0]&0xf}, r{args[1]&0xf}, {sx32(v)}"
    elif cls == 7:
        v = struct.unpack_from("<I", raw, 1)[0]
        txt = f"-> 0x{pc + ln + sx32(v):04x}" + (f" ({sx32(v)})" if sx32(v) != v else "")
    elif cls == 8:
        v = struct.unpack_from("<I", raw, 1)[0]
        if op == 0x0a: txt = f"{v}" + (f" <{NATIVE.get(v,'?')}>" if v in NATIVE else " <INVALID>")
        else: txt = f"len=0x{v:x}"
    return pc, ln, op, name, txt

def disasm(start=0, end=None):
    end = end or len(bc)
    pc = start
    lines = []
    while pc < end:
        d = decode(pc)
        if d is None:
            lines.append(f"  {pc:04x}: ?? opcode 0x{bc[pc]:02x}")
            break
        p, ln, op, name, txt = d
        hexb = bc[p:p+ln].hex()
        lines.append(f"  {p:04x}: {hexb:20s} {name:8s} {txt}")
        pc += ln
    return "\n".join(lines)

if __name__ == "__main__":
    a = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0
    b = int(sys.argv[2], 0) if len(sys.argv) > 2 else None
    print(disasm(a, b))

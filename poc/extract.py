#!/usr/bin/env python3
"""BLKernel RE - Stage 0: full static unpacker.
   Derives the .blkcode key from CRC32(.text) and decrypts the BLKVMC01
   container (bytecode + VM data) WITHOUT executing the binary.
   Vulnerability BLK-RE-001: cipher key is file-derived => offline decrypt."""
import pefile, struct, sys, os

GOLDEN = 0x9E3779B97F4A7C15
M1 = 0xBF58476D1CE4E5B9
M2 = 0x94D049BB133111EB
XCONST = 0x5A17C0DE5A17C0DE
M64 = (1 << 64) - 1

def crc_raw(data, init=0):
    crc = init
    for b in data:
        v = b ^ crc
        for _ in range(8):
            lsb = v & 1
            v >>= 1
            if lsb: v ^= 0xEDB88320
        crc = v
    return crc & 0xFFFFFFFF

def sm_final(x):
    x &= M64; x ^= x >> 30; x = (x * M1) & M64
    x ^= x >> 27; x = (x * M2) & M64; x ^= x >> 31
    return x

def decrypt(buf, key64, size):
    data = bytearray(buf[:size])
    n = size // 8
    for i in range(n):
        x = ((i * GOLDEN) & M64) ^ key64 ^ (size & M64)
        ks = sm_final(x)
        w = struct.unpack_from("<Q", data, i * 8)[0]
        struct.pack_into("<Q", data, i * 8, w ^ ks)
    tailn = size & 7
    if tailn:
        i = n
        x = ((i * GOLDEN) & M64) ^ key64 ^ (size & M64)
        ks = sm_final(x)
        tail = bytes(data[i*8:i*8+tailn]) + b"\x00" * (8 - tailn)
        w = struct.unpack("<Q", tail)[0]
        data[i*8:i*8+tailn] = struct.pack("<Q", w ^ ks)[:tailn]
    return bytes(data)

def main(pe_path, outdir):
    pe = pefile.PE(pe_path)
    raw = open(pe_path, "rb").read()
    text = blk = None
    blk_vsize = 0
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00")
        if nm == b".text":
            text = raw[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        if nm == b".blkcode":
            blk = raw[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
            blk_vsize = s.Misc_VirtualSize
    seed = crc_raw(text, 0)
    K = ((seed * GOLDEN) & M64) ^ XCONST
    dec = decrypt(blk, K, blk_vsize)
    assert dec[:8] == b"BLKVMC01", f"bad magic {dec[:8]!r}"
    payload_size, data_size = struct.unpack_from("<QQ", dec, 8)
    bytecode = dec[0x18:0x18 + payload_size]
    vdata = dec[0x18 + payload_size:0x18 + payload_size + data_size]
    os.makedirs(outdir, exist_ok=True)
    open(os.path.join(outdir, "vm_bytecode.bin"), "wb").write(bytecode)
    open(os.path.join(outdir, "vm_data.bin"), "wb").write(vdata)
    print(f"[+] seed (CRC32 .text) = {seed:#010x}")
    print(f"[+] K = {K:#018x}")
    print(f"[+] BLKVMC01 container: bytecode {payload_size:#x} bytes, data {data_size:#x} bytes")
    print(f"[+] wrote {outdir}/vm_bytecode.bin and vm_data.bin")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "BLKernel.exe",
         sys.argv[2] if len(sys.argv) > 2 else ".")

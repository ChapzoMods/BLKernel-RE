// BLKernel keygen stage 1: recover r8_true from the encrypted 512-byte blob.
// Known plaintext: word0 low32 = "BLK!" (0x214B4C42). Message assumed printable ASCII
// (it is printed verbatim by the crackme). Final arbiter: internal hash-chain check.
//
// For candidate pt0 = 0x????????214B4C42 (high32 unknown, iterated 2^32):
//   ks0 = ct0 ^ pt0 ;  r8 = inv_splitmix(ks0) ^ 512 ^ (0*GOLDEN)
//   then filter with word1/word2 ASCII and verify full hash chain.
//
// gcc -O3 -march=native -funroll-loops -o keygen_stage1 keygen_stage1.c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const uint64_t M1 = 0xBF58476D1CE4E5B9ULL;
static const uint64_t M2 = 0x94D049BB133111EBULL;
static const uint64_t GOLDEN = 0x9E3779B97F4A7C15ULL;
static const uint64_t M1_INV = 0x96de1b173f119089ULL;
static const uint64_t M2_INV = 0x319642b2d24d8ec3ULL;

static inline uint64_t sm(uint64_t x) {
    x ^= x >> 30; x *= M1;
    x ^= x >> 27; x *= M2;
    x ^= x >> 31; return x;
}
static inline uint64_t unxsr(uint64_t y, int s) {
    uint64_t x = y;
    for (int i = 0; i <= 64 / s; i++) x = y ^ (x >> s);
    return x;
}
static inline uint64_t inv_sm(uint64_t y) {
    uint64_t x = unxsr(y, 31);
    x *= M2_INV;
    x = unxsr(x, 27);
    x *= M1_INV;
    x = unxsr(x, 30);
    return x;
}
static inline int ascii_ok(uint64_t w) {
    // printable ASCII 0x20..0x7e for all 8 bytes
    for (int i = 0; i < 8; i++) {
        unsigned c = (w >> (8*i)) & 0xff;
        if (c < 0x20 || c > 0x7e) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    FILE *f = fopen("/home/z/my-project/re_workspace/vm_data.bin", "rb");
    if (!f) { perror("data"); return 1; }
    uint8_t *data = malloc(0x150e);
    fread(data, 1, 0x150e, f); fclose(f);
    uint64_t *ct = (uint64_t *)(data + 0x1000);   // 64 words ciphertext

    const uint64_t BLOB_KEY_OFFSET = 512;         // the XORI 512 in keystream
    const uint32_t MAGIC = 0x214B4C42ULL;         // "BLK!"

    // sanity: verify self-check of inv_sm
    for (uint64_t t = 0; t < 1000; t++) if (inv_sm(sm(t)) != t) { printf("inv_sm broken\n"); return 1; }

    fprintf(stderr, "[*] scanning 2^32 candidates for word0...\n");
    long long survivors = 0;
    for (uint64_t hi = 0; ; hi++) {
        uint64_t pt0 = (hi << 32) | MAGIC;
        uint64_t ks0 = ct[0] ^ pt0;
        uint64_t r8 = inv_sm(ks0) ^ BLOB_KEY_OFFSET;
        // word1 filter
        uint64_t pt1 = ct[1] ^ sm(GOLDEN ^ BLOB_KEY_OFFSET ^ r8);
        if (!ascii_ok(pt1)) goto next;
        {
            uint64_t pt2 = ct[2] ^ sm(2*GOLDEN ^ BLOB_KEY_OFFSET ^ r8);
            if (!ascii_ok(pt2)) goto next;
            uint64_t pt3 = ct[3] ^ sm(3*GOLDEN ^ BLOB_KEY_OFFSET ^ r8);
            if (!ascii_ok(pt3)) goto next;
            uint64_t pt4 = ct[4] ^ sm(4*GOLDEN ^ BLOB_KEY_OFFSET ^ r8);
            if (!ascii_ok(pt4)) goto next;
        }
        // full chain check
        {
            uint64_t chain = 0;
            int ok = 1;
            for (int i = 0; i < 63; i++) {
                uint64_t ks = sm((uint64_t)i * GOLDEN ^ BLOB_KEY_OFFSET ^ r8);
                chain ^= ct[i] ^ ks;
                chain = sm(chain);
            }
            uint64_t pt63 = ct[63] ^ sm(63*GOLDEN ^ BLOB_KEY_OFFSET ^ r8);
            if (chain != pt63) ok = 0;
            if (ok) {
                // full decrypt + report
                printf("FOUND r8 = 0x%016llx\n", (unsigned long long)r8);
                printf("pt0 = 0x%016llx\n", (unsigned long long)pt0);
                uint8_t msg[512];
                for (int i = 0; i < 64; i++) {
                    uint64_t ks = sm((uint64_t)i * GOLDEN ^ BLOB_KEY_OFFSET ^ r8);
                    uint64_t w = ct[i] ^ ks;
                    memcpy(msg + 8*i, &w, 8);
                }
                FILE *g = fopen("/home/z/my-project/re_workspace/blob_plain.bin", "wb");
                fwrite(msg, 1, 512, g); fclose(g);
                fprintf(stderr, "[+] plaintext saved to blob_plain.bin\n");
                fprintf(stderr, "msg: ");
                for (int i = 0; i < 96; i++) fputc(msg[i] >= 32 && msg[i] < 127 ? msg[i] : '.', stderr);
                fprintf(stderr, "\n");
                survivors++;
            }
        }
next:
        if (hi == 0xffffffffULL) break;
        if ((hi & 0xfffffffULL) == 0) fprintf(stderr, "  progress: %llu/2^32\n", (unsigned long long)hi);
    }
    fprintf(stderr, "[*] done, %lld solutions\n", survivors);
    return 0;
}

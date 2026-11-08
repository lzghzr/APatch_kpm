#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#define CHUNK_SIZE (1024 * 1024)  // 1 MiB per I/O chunk
#define DEFAULT_SIZE (256 * 1024 * 1024) // 256 MiB

/* Freestanding SHA-256 implementation */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} SHA256_CTX;

static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    for (; i < 64; ++i) {
        uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + m[i];
        t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0, index = (size_t)((ctx->count >> 3) & 0x3f);
    ctx->count += (uint64_t)len << 3;
    size_t partLen = 64 - index;
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], data, partLen);
        sha256_transform(ctx, ctx->buffer);
        for (i = partLen; i + 63 < len; i += 64)
            sha256_transform(ctx, &data[i]);
        index = 0;
    }
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]) {
    static const uint8_t padding[64] = { 0x80 };
    uint8_t bits[8];
    for (int i = 0; i < 8; ++i)
        bits[i] = (uint8_t)((ctx->count >> ((7 - i) * 8)) & 0xff);
    size_t index = (size_t)((ctx->count >> 3) & 0x3f);
    size_t padLen = (index < 56) ? (56 - index) : (120 - index);
    sha256_update(ctx, padding, padLen);
    sha256_update(ctx, bits, 8);
    for (int i = 0; i < 8; ++i) {
        hash[i * 4]     = (uint8_t)((ctx->state[i] >> 24) & 0xff);
        hash[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
        hash[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xff);
    }
}

static void hash_to_hex(const uint8_t hash[32], char hex[65]) {
    for (int i = 0; i < 32; ++i)
        sprintf(hex + (i * 2), "%02x", hash[i]);
    hex[64] = 0;
}

static void calc_sha256(const uint8_t *data, size_t len, char hex[65]) {
    SHA256_CTX ctx;
    uint8_t hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
    hash_to_hex(hash, hex);
}

static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + (ts.tv_nsec / 1e9);
}

typedef struct {
    unsigned long long orig_data_size;
    unsigned long long compr_data_size;
    unsigned long long mem_used_total;
} mm_stat_t;

static int read_mm_stat(const char *sys_path, mm_stat_t *st) {
    FILE *f = fopen(sys_path, "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    int ret = sscanf(line, "%llu %llu %llu",
                     &st->orig_data_size, &st->compr_data_size, &st->mem_used_total);
    return (ret >= 2) ? 0 : -1;
}

int main(int argc, char **argv) {
    const char *corpus_path = "/data/local/tmp/corpus_256m.bin";
    const char *dev_path = "/dev/block/zram0";
    const char *mm_stat_path = "/sys/block/zram0/mm_stat";
    size_t total_bytes = DEFAULT_SIZE;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--corpus") == 0 && i + 1 < argc) corpus_path = argv[++i];
        else if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) dev_path = argv[++i];
        else if (strcmp(argv[i], "--mm-stat") == 0 && i + 1 < argc) mm_stat_path = argv[++i];
        else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) total_bytes = (size_t)atoll(argv[++i]);
    }

    fprintf(stderr, "[*] Loading corpus: %s (%zu bytes)\n", corpus_path, total_bytes);
    uint8_t *corpus_buf = NULL;
    if (posix_memalign((void **)&corpus_buf, 4096, total_bytes) != 0 || !corpus_buf) {
        fprintf(stderr, "[-] Failed to allocate %zu bytes for corpus_buf\n", total_bytes);
        return 1;
    }

    int cfd = open(corpus_path, O_RDONLY);
    if (cfd < 0) {
        fprintf(stderr, "[-] Failed to open corpus %s: %s\n", corpus_path, strerror(errno));
        free(corpus_buf);
        return 1;
    }
    size_t c_read = 0;
    while (c_read < total_bytes) {
        ssize_t n = read(cfd, corpus_buf + c_read, total_bytes - c_read);
        if (n <= 0) {
            fprintf(stderr, "[-] Corpus read truncated at %zu bytes: %s\n", c_read, strerror(errno));
            close(cfd);
            free(corpus_buf);
            return 1;
        }
        c_read += n;
    }
    close(cfd);

    char corpus_sha[65];
    calc_sha256(corpus_buf, total_bytes, corpus_sha);
    fprintf(stderr, "[*] Corpus loaded. SHA-256: %s\n", corpus_sha);

    uint8_t *read_buf = NULL;
    if (posix_memalign((void **)&read_buf, 4096, total_bytes) != 0 || !read_buf) {
        fprintf(stderr, "[-] Failed to allocate %zu bytes for read_buf\n", total_bytes);
        free(corpus_buf);
        return 1;
    }

    // Open target zram device with O_DIRECT | O_SYNC
    int zfd = open(dev_path, O_RDWR | O_DIRECT | O_SYNC);
    if (zfd < 0) {
        fprintf(stderr, "[-] Failed to open %s: %s\n", dev_path, strerror(errno));
        free(corpus_buf);
        free(read_buf);
        return 1;
    }

    mm_stat_t mm_before = {0}, mm_after = {0};
    read_mm_stat(mm_stat_path, &mm_before);

    // --- TIMED WRITE ---
    fprintf(stderr, "[*] Starting timed sequential write (%zu bytes)...\n", total_bytes);
    double t_w0 = get_time_sec();
    size_t written = 0;
    while (written < total_bytes) {
        size_t chunk = (total_bytes - written > CHUNK_SIZE) ? CHUNK_SIZE : (total_bytes - written);
        ssize_t n = write(zfd, corpus_buf + written, chunk);
        if (n <= 0) {
            fprintf(stderr, "[-] Write failed at offset %zu: %s (errno=%d)\n", written, strerror(errno), errno);
            close(zfd);
            free(corpus_buf);
            free(read_buf);
            return 1;
        }
        written += n;
    }
    fsync(zfd);
    double t_w1 = get_time_sec();
    double write_sec = t_w1 - t_w0;
    double comp_mib_s = (total_bytes / (1024.0 * 1024.0)) / write_sec;
    fprintf(stderr, "[+] Write complete: %zu bytes in %.4f s (%.2f MiB/s)\n", total_bytes, write_sec, comp_mib_s);

    if (read_mm_stat(mm_stat_path, &mm_after) != 0) {
        fprintf(stderr, "[-] Failed to read mm_stat after write\n");
    }
    double comp_ratio = (mm_after.compr_data_size > 0) ?
        ((double)mm_after.orig_data_size / (double)mm_after.compr_data_size) : 0.0;
    fprintf(stderr, "[+] mm_stat: orig=%llu, compr=%llu, ratio=%.4f:1\n",
            mm_after.orig_data_size, mm_after.compr_data_size, comp_ratio);

    // Flush cache & reset pointer before reading
    ioctl(zfd, BLKFLSBUF, 0);
    posix_fadvise(zfd, 0, total_bytes, POSIX_FADV_DONTNEED);
    lseek(zfd, 0, SEEK_SET);

    // --- TIMED READBACK ---
    fprintf(stderr, "[*] Starting timed sequential readback (%zu bytes)...\n", total_bytes);
    double t_r0 = get_time_sec();
    size_t bytes_read = 0;
    while (bytes_read < total_bytes) {
        size_t chunk = (total_bytes - bytes_read > CHUNK_SIZE) ? CHUNK_SIZE : (total_bytes - bytes_read);
        ssize_t n = read(zfd, read_buf + bytes_read, chunk);
        if (n <= 0) {
            fprintf(stderr, "[-] Readback failed at offset %zu: %s (errno=%d)\n", bytes_read, strerror(errno), errno);
            close(zfd);
            free(corpus_buf);
            free(read_buf);
            return 1;
        }
        bytes_read += n;
    }
    double t_r1 = get_time_sec();
    double read_sec = t_r1 - t_r0;
    double decomp_mib_s = (total_bytes / (1024.0 * 1024.0)) / read_sec;
    fprintf(stderr, "[+] Readback complete: %zu bytes in %.4f s (%.2f MiB/s)\n", total_bytes, read_sec, decomp_mib_s);

    close(zfd);

    // --- VERIFY INTEGRITY ---
    char read_sha[65];
    calc_sha256(read_buf, total_bytes, read_sha);
    int memcmp_res = memcmp(corpus_buf, read_buf, total_bytes);
    int match = (memcmp_res == 0 && strcmp(corpus_sha, read_sha) == 0);

    if (!match) {
        fprintf(stderr, "[-] DATA INTEGRITY FAILURE! Readback does not match corpus!\n");
        fprintf(stderr, "[-] Corpus SHA-256:   %s\n", corpus_sha);
        fprintf(stderr, "[-] Readback SHA-256: %s\n", read_sha);
        // Find first mismatch offset
        for (size_t off = 0; off < total_bytes; ++off) {
            if (corpus_buf[off] != read_buf[off]) {
                fprintf(stderr, "[-] First mismatch at byte %zu (0x%zx): expected 0x%02x, got 0x%02x\n",
                        off, off, corpus_buf[off], read_buf[off]);
                break;
            }
        }
    } else {
        fprintf(stderr, "[+] DATA INTEGRITY PASS: 100%% byte-for-byte match (SHA-256: %s)\n", read_sha);
    }

    // Output JSON for parsing
    printf("{\n");
    printf("  \"status\": \"%s\",\n", match ? "PASS" : "FAIL");
    printf("  \"total_bytes\": %zu,\n", total_bytes);
    printf("  \"orig_data_size\": %llu,\n", mm_after.orig_data_size);
    printf("  \"compr_data_size\": %llu,\n", mm_after.compr_data_size);
    printf("  \"mem_used_total\": %llu,\n", mm_after.mem_used_total);
    printf("  \"compression_ratio\": %.6f,\n", comp_ratio);
    printf("  \"write_time_sec\": %.6f,\n", write_sec);
    printf("  \"compress_mib_s\": %.2f,\n", comp_mib_s);
    printf("  \"read_time_sec\": %.6f,\n", read_sec);
    printf("  \"decompress_mib_s\": %.2f,\n", decomp_mib_s);
    printf("  \"corpus_sha256\": \"%s\",\n", corpus_sha);
    printf("  \"read_sha256\": \"%s\",\n", read_sha);
    printf("  \"integrity_match\": %s\n", match ? "true" : "false");
    printf("}\n");

    free(corpus_buf);
    free(read_buf);
    return match ? 0 : 2;
}

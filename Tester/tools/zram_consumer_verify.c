#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#define CHUNK_SIZE (64 * 1024 * 1024) // 64 MB per chunk
#define MAX_CHUNKS 256                // Up to 16 GB (for high-RAM devices)

// Simple MD5 implementation for reporting
typedef struct {
    unsigned int state[4];
    unsigned int count[2];
    unsigned char buffer[64];
} MD5_CTX;

static void MD5Transform(unsigned int state[4], const unsigned char block[64]);
static void MD5Init(MD5_CTX *context);
static void MD5Update(MD5_CTX *context, const unsigned char *input, unsigned int inputLen);
static void MD5Final(unsigned char digest[16], MD5_CTX *context);

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Init(MD5_CTX *context) {
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

static void MD5Transform(unsigned int state[4], const unsigned char block[64]) {
    unsigned int a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    for (int i = 0, j = 0; j < 64; i++, j += 4)
        x[i] = ((unsigned int)block[j]) | (((unsigned int)block[j+1]) << 8) |
               (((unsigned int)block[j+2]) << 16) | (((unsigned int)block[j+3]) << 24);

    FF (a, b, c, d, x[ 0], S11, 0xd76aa478);
    FF (d, a, b, c, x[ 1], S12, 0xe8c7b756);
    FF (c, d, a, b, x[ 2], S13, 0x242070db);
    FF (b, c, d, a, x[ 3], S14, 0xc1bdceee);
    FF (a, b, c, d, x[ 4], S11, 0xf57c0faf);
    FF (d, a, b, c, x[ 5], S12, 0x4787c62a);
    FF (c, d, a, b, x[ 6], S13, 0xa8304613);
    FF (b, c, d, a, x[ 7], S14, 0xfd469501);
    FF (a, b, c, d, x[ 8], S11, 0x698098d8);
    FF (d, a, b, c, x[ 9], S12, 0x8b44f7af);
    FF (c, d, a, b, x[10], S13, 0xffff5bb1);
    FF (b, c, d, a, x[11], S14, 0x895cd7be);
    FF (a, b, c, d, x[12], S11, 0x6b901122);
    FF (d, a, b, c, x[13], S12, 0xfd987193);
    FF (c, d, a, b, x[14], S13, 0xa679438e);
    FF (b, c, d, a, x[15], S14, 0x49b40821);

    GG (a, b, c, d, x[ 1], S21, 0xf61e2562);
    GG (d, a, b, c, x[ 6], S22, 0xc040b340);
    GG (c, d, a, b, x[11], S23, 0x265e5a51);
    GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa);
    GG (a, b, c, d, x[ 5], S21, 0xd62f105d);
    GG (d, a, b, c, x[10], S22,  0x2441453);
    GG (c, d, a, b, x[15], S23, 0xd8a1e681);
    GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8);
    GG (a, b, c, d, x[ 9], S21, 0x21e1cde6);
    GG (d, a, b, c, x[14], S22, 0xc33707d6);
    GG (c, d, a, b, x[ 3], S23, 0xf4d50d87);
    GG (b, c, d, a, x[ 8], S24, 0x455a14ed);
    GG (a, b, c, d, x[13], S21, 0xa9e3e905);
    GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8);
    GG (c, d, a, b, x[ 7], S23, 0x676f02d9);
    GG (b, c, d, a, x[12], S24, 0x8d2a4c8a);

    HH (a, b, c, d, x[ 5], S31, 0xfffa3942);
    HH (d, a, b, c, x[ 8], S32, 0x8771f681);
    HH (c, d, a, b, x[11], S33, 0x6d9d6122);
    HH (b, c, d, a, x[14], S34, 0xfde5380c);
    HH (a, b, c, d, x[ 1], S31, 0xa4beea44);
    HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9);
    HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60);
    HH (b, c, d, a, x[10], S34, 0xbebfbc70);
    HH (a, b, c, d, x[13], S31, 0x289b7ec6);
    HH (d, a, b, c, x[ 0], S32, 0xeaa127fa);
    HH (c, d, a, b, x[ 3], S33, 0xd4ef3085);
    HH (b, c, d, a, x[ 6], S34,  0x4881d05);
    HH (a, b, c, d, x[ 9], S31, 0xd9d4d039);
    HH (d, a, b, c, x[12], S32, 0xe6db99e5);
    HH (c, d, a, b, x[15], S33, 0x1fa27cf8);
    HH (b, c, d, a, x[ 2], S34, 0xc4ac5665);

    II (a, b, c, d, x[ 0], S41, 0xf4292244);
    II (d, a, b, c, x[ 7], S42, 0x432aff97);
    II (c, d, a, b, x[14], S43, 0xab9423a7);
    II (b, c, d, a, x[ 5], S44, 0xfc93a039);
    II (a, b, c, d, x[12], S41, 0x655b59c3);
    II (d, a, b, c, x[ 3], S42, 0x8f0ccc92);
    II (c, d, a, b, x[10], S43, 0xffeff47d);
    II (b, c, d, a, x[ 1], S44, 0x85845dd1);
    II (a, b, c, d, x[ 8], S41, 0x6fa87e4f);
    II (d, a, b, c, x[15], S42, 0xfe2ce6e0);
    II (c, d, a, b, x[ 6], S43, 0xa3014314);
    II (b, c, d, a, x[13], S44, 0x4e0811a1);
    II (a, b, c, d, x[ 4], S41, 0xf7537e82);
    II (d, a, b, c, x[11], S42, 0xbd3af235);
    II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb);
    II (b, c, d, a, x[ 9], S44, 0xeb86d391);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void MD5Update(MD5_CTX *context, const unsigned char *input, unsigned int inputLen) {
    unsigned int i = 0, index = (unsigned int)((context->count[0] >> 3) & 0x3F);
    if ((context->count[0] += ((unsigned int)inputLen << 3)) < ((unsigned int)inputLen << 3))
        context->count[1]++;
    context->count[1] += ((unsigned int)inputLen >> 29);
    unsigned int partLen = 64 - index;
    if (inputLen >= partLen) {
        memcpy(&context->buffer[index], input, partLen);
        MD5Transform(context->state, context->buffer);
        for (i = partLen; i + 63 < inputLen; i += 64)
            MD5Transform(context->state, &input[i]);
        index = 0;
    }
    memcpy(&context->buffer[index], &input[i], inputLen - i);
}

static void MD5Final(unsigned char digest[16], MD5_CTX *context) {
    static unsigned char PADDING[64] = { 0x80 };
    unsigned char bits[8];
    for (int i = 0; i < 4; i++) {
        bits[i] = (unsigned char)((context->count[0] >> (i * 8)) & 0xFF);
        bits[i+4] = (unsigned char)((context->count[1] >> (i * 8)) & 0xFF);
    }
    unsigned int index = (unsigned int)((context->count[0] >> 3) & 0x3f);
    unsigned int padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(context, PADDING, padLen);
    MD5Update(context, bits, 8);
    for (int i = 0; i < 4; i++) {
        digest[i]   = (unsigned char)((context->state[0] >> (i * 8)) & 0xFF);
        digest[i+4] = (unsigned char)((context->state[1] >> (i * 8)) & 0xFF);
        digest[i+8] = (unsigned char)((context->state[2] >> (i * 8)) & 0xFF);
        digest[i+12]= (unsigned char)((context->state[3] >> (i * 8)) & 0xFF);
    }
}

static void hex_md5(const unsigned char digest[16], char out[33]) {
    for (int i = 0; i < 16; i++) {
        sprintf(out + (i * 2), "%02x", digest[i]);
    }
    out[32] = 0;
}

// Generate predictable, compressible test pattern
static inline unsigned char get_pattern_byte(size_t chunk_idx, size_t offset) {
    size_t page_idx = offset / 4096;
    size_t page_off = offset % 4096;
    return (unsigned char)(((chunk_idx * 31) ^ (page_idx * 17) ^ ((page_off / 64) * 11) ^ (page_off % 16)) & 0xff);
}

static long read_swap_used_kb() {
    FILE *f = fopen("/proc/swaps", "r");
    if (!f) return -1;
    char line[256];
    long used = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "zram0")) {
            char name[64], type[64];
            long size = 0, u = 0, prio = 0;
            if (sscanf(line, "%s %s %ld %ld %ld", name, type, &size, &u, &prio) >= 4) {
                used = u;
                break;
            }
        }
    }
    fclose(f);
    return used;
}

static void print_mm_stat() {
    FILE *f = fopen("/sys/block/zram0/mm_stat", "r");
    if (!f) return;
    char line[256];
    if (fgets(line, sizeof(line), f)) {
        printf("[mm_stat] %s", line);
    }
    fclose(f);
}

// 1. Direct block I/O test
int run_block_io_test(const char *dev_path, size_t size_mb) {
    size_t total_bytes = size_mb * 1024 * 1024;
    printf("=== Starting Direct Block I/O Test (%zu MB on %s) ===\n", size_mb, dev_path);
    fflush(stdout);

    unsigned char *write_buf = malloc(total_bytes);
    unsigned char *read_buf = malloc(total_bytes);
    if (!write_buf || !read_buf) {
        fprintf(stderr, "[-] Out of memory for I/O buffers\n");
        return 1;
    }

    // Fill with predictable pattern
    for (size_t i = 0; i < total_bytes; i++) {
        write_buf[i] = get_pattern_byte(0, i);
    }

    MD5_CTX ctx;
    unsigned char digest_in[16], digest_out[16];
    char md5_in[33], md5_out[33];

    MD5Init(&ctx);
    MD5Update(&ctx, write_buf, total_bytes);
    MD5Final(digest_in, &ctx);
    hex_md5(digest_in, md5_in);
    printf("IN_MD5: %s\n", md5_in);

    int fd = open(dev_path, O_RDWR | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "[-] Failed to open %s: %s\n", dev_path, strerror(errno));
        free(write_buf);
        free(read_buf);
        return 1;
    }

    // Write
    size_t written = 0;
    while (written < total_bytes) {
        ssize_t ret = write(fd, write_buf + written, total_bytes - written);
        if (ret <= 0) {
            fprintf(stderr, "[-] Write failed at %zu: %s\n", written, strerror(errno));
            close(fd);
            free(write_buf);
            free(read_buf);
            return 1;
        }
        written += ret;
    }
    fsync(fd);
    printf("[+] Wrote %zu bytes to %s\n", written, dev_path);
    print_mm_stat();

    // Read back
    lseek(fd, 0, SEEK_SET);
    size_t read_bytes = 0;
    while (read_bytes < total_bytes) {
        ssize_t ret = read(fd, read_buf + read_bytes, total_bytes - read_bytes);
        if (ret <= 0) {
            fprintf(stderr, "[-] Read failed at %zu: %s\n", read_bytes, strerror(errno));
            close(fd);
            free(write_buf);
            free(read_buf);
            return 1;
        }
        read_bytes += ret;
    }
    close(fd);
    printf("[+] Read %zu bytes back from %s\n", read_bytes, dev_path);

    MD5Init(&ctx);
    MD5Update(&ctx, read_buf, total_bytes);
    MD5Final(digest_out, &ctx);
    hex_md5(digest_out, md5_out);
    printf("OUT_MD5: %s\n", md5_out);

    if (strcmp(md5_in, md5_out) == 0 && memcmp(write_buf, read_buf, total_bytes) == 0) {
        printf("ZRAM_IO_VERIFY=PASS md5=%s bytes=%zu\n", md5_out, total_bytes);
        free(write_buf);
        free(read_buf);
        return 0;
    } else {
        printf("ZRAM_IO_VERIFY=FAIL mismatch!\n");
        free(write_buf);
        free(read_buf);
        return 1;
    }
}

// 2. Real consumer swap pressure test
int run_swap_consumer_test(size_t target_mb, size_t min_swap_kb) {
    int oom_fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (oom_fd >= 0) {
        write(oom_fd, "-1000", 5);
        close(oom_fd);
    }

    printf("=== Starting Real Consumer Swap Pressure Test (Target: %zu MB, MinSwap: %zu KB) ===\n", target_mb, min_swap_kb);
    printf("[*] Consumer running under pid=%d, uid=%d (oom_score_adj=-1000)\n", getpid(), getuid());
    fflush(stdout);

    long initial_swap = read_swap_used_kb();
    printf("[*] Initial swap used: %ld KB\n", initial_swap);
    print_mm_stat();

    size_t num_chunks = target_mb / 64;
    if (num_chunks > MAX_CHUNKS) num_chunks = MAX_CHUNKS;
    if (num_chunks < 1) num_chunks = 1;

    void *chunks[MAX_CHUNKS];
    size_t allocated_chunks = 0;

    printf("[*] Allocating up to %zu chunks (%zu MB) of anonymous memory...\n", num_chunks, num_chunks * 64);
    fflush(stdout);

    for (size_t c = 0; c < num_chunks; c++) {
        chunks[c] = mmap(NULL, CHUNK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (chunks[c] == MAP_FAILED) {
            printf("[!] mmap hit limit at chunk %zu (%zu MB allocated)\n", c, c * 64);
            break;
        }
        allocated_chunks++;

        // Populate with deterministic pattern
        unsigned char *p = (unsigned char *)chunks[c];
        for (size_t i = 0; i < CHUNK_SIZE; i += 64) {
            unsigned char b = get_pattern_byte(c, i);
            memset(p + i, b, 64);
        }

        long cur_swap = read_swap_used_kb();
        if ((c + 1) % 4 == 0 || cur_swap > initial_swap) {
            printf("[*] Chunk %zu/%zu (%zu MB) -> Swap Used: %ld KB\n",
                   c + 1, num_chunks, (c + 1) * 64, cur_swap);
            fflush(stdout);
        }

        if (min_swap_kb > 0 && cur_swap >= (long)min_swap_kb) {
            printf("[+] Reached target minimum swap: %ld KB >= %zu KB at chunk %zu (%zu MB)\n",
                   cur_swap, min_swap_kb, c + 1, (c + 1) * 64);
            fflush(stdout);
            break;
        }
    }

    printf("[+] Total allocated by consumer: %zu MB across %zu chunks\n",
           allocated_chunks * 64, allocated_chunks);
    fflush(stdout);

    // Let the kernel settle and check swap usage
    sleep(2);
    long swapped = read_swap_used_kb();
    printf("[*] Active swap used under memory pressure: %ld KB (net swapped: %ld KB)\n",
           swapped, swapped - initial_swap);
    print_mm_stat();
    fflush(stdout);

    // Verify swap pressure achieved
    int swap_observed = (swapped > 0);
    int target_met = (min_swap_kb == 0 || swapped >= (long)min_swap_kb);
    printf("[*] Swap utilization criterion (Used > 0): %s (used=%ld KB)\n",
           swap_observed ? "MET (PASS)" : "NOT MET", swapped);
    if (min_swap_kb > 0) {
        printf("[*] Minimum swap target criterion (>= %zu KB): %s (used=%ld KB)\n",
               min_swap_kb, target_met ? "MET (PASS)" : "NOT MET (FAIL)", swapped);
    }
    fflush(stdout);

    // 3. Roundtrip data integrity verification: read back all pages!
    printf("[*] Reading back and verifying all %zu MB anonymous memory from consumer...\n",
           allocated_chunks * 64);
    fflush(stdout);

    size_t verified_bytes = 0;
    size_t mismatches = 0;

    for (size_t c = 0; c < allocated_chunks; c++) {
        unsigned char *p = (unsigned char *)chunks[c];
        for (size_t i = 0; i < CHUNK_SIZE; i += 64) {
            unsigned char expected = get_pattern_byte(c, i);
            for (size_t k = 0; k < 64; k++) {
                if (p[i + k] != expected) {
                    if (mismatches < 5) {
                        fprintf(stderr, "[-] Data mismatch at chunk %zu offset 0x%zx: got 0x%02x expected 0x%02x\n",
                                c, i + k, p[i + k], expected);
                    }
                    mismatches++;
                }
            }
            verified_bytes += 64;
        }
    }

    printf("[+] Memory verification complete: %zu bytes verified, mismatches: %zu\n",
           verified_bytes, mismatches);
    print_mm_stat();
    fflush(stdout);

    // Clean up
    for (size_t c = 0; c < allocated_chunks; c++) {
        munmap(chunks[c], CHUNK_SIZE);
    }

    if (mismatches == 0 && swap_observed && target_met) {
        printf("CONSUMER_ROUNDTRIP_VERIFY=PASS verified_bytes=%zu swap_used_kb=%ld\n",
               verified_bytes, swapped);
        return 0;
    } else if (mismatches == 0 && swap_observed) {
        printf("CONSUMER_ROUNDTRIP_VERIFY=PASS_UNDER_TARGET verified_bytes=%zu swap_used_kb=%ld (required %zu KB)\n",
               verified_bytes, swapped, min_swap_kb);
        return 2;
    } else if (mismatches == 0) {
        printf("CONSUMER_ROUNDTRIP_VERIFY=PASS_NO_SWAP (data intact, but swap_used was %ld KB)\n", swapped);
        return 3;
    } else {
        printf("CONSUMER_ROUNDTRIP_VERIFY=FAIL mismatches=%zu\n", mismatches);
        return 1;
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--block-io") == 0) {
        const char *dev = (argc > 2) ? argv[2] : "/dev/block/zram0";
        size_t mb = (argc > 3) ? (size_t)atoi(argv[3]) : 8;
        return run_block_io_test(dev, mb);
    } else if (argc > 1 && strcmp(argv[1], "--swap-consumer") == 0) {
        size_t mb = (argc > 2) ? (size_t)atoi(argv[2]) : 3072; // default 3 GB
        size_t min_swap_kb = (argc > 3) ? (size_t)atoi(argv[3]) : 0;
        return run_swap_consumer_test(mb, min_swap_kb);
    } else {
        printf("Usage:\n");
        printf("  %s --block-io [/dev/block/zram0] [size_mb]\n", argv[0]);
        printf("  %s --swap-consumer [target_mb] [min_swap_kb]\n", argv[0]);
        return 1;
    }
}

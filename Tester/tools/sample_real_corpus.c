#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#define PAGE_SIZE 4096

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

static pid_t find_pid_by_name(const char *needle) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *de;
    pid_t result = -1;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(de->d_name);
        char cmdpath[64];
        snprintf(cmdpath, sizeof(cmdpath), "/proc/%d/cmdline", pid);
        FILE *f = fopen(cmdpath, "r");
        if (!f) continue;
        char cmd[256] = {0};
        size_t n = fread(cmd, 1, sizeof(cmd) - 1, f);
        fclose(f);
        if (n > 0) {
            for (size_t i = 0; i < n; ++i) if (cmd[i] == '\0') cmd[i] = ' ';
            if (strstr(cmd, needle)) {
                result = pid;
                break;
            }
        }
    }
    closedir(d);
    return result;
}

typedef struct {
    const char *category_name;
    const char *class_type; // "anon" or "file"
    const char *target_desc;
    size_t target_pages;
    size_t target_bytes;
    size_t sampled_pages;
    size_t skipped_pages;
    char skip_reason[128];
    char sha256_hex[65];
} segment_info_t;

int main(int argc, char **argv) {
    const char *out_path = "/data/local/tmp/corpus_real_256m.bin";
    const char *out_slices_dir = "/data/local/tmp/corpus_real";
    const char *manifest_path = "/data/local/tmp/corpus_real_manifest.json";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) out_path = argv[++i];
        else if (strcmp(argv[i], "--slices") == 0 && i + 1 < argc) out_slices_dir = argv[++i];
        else if (strcmp(argv[i], "--manifest") == 0 && i + 1 < argc) manifest_path = argv[++i];
    }

    mkdir(out_slices_dir, 0755);

    int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        fprintf(stderr, "[-] Failed to open output file %s: %s\n", out_path, strerror(errno));
        return 1;
    }

    SHA256_CTX total_ctx;
    sha256_init(&total_ctx);

    segment_info_t segments[] = {
        /* Part 1: Anonymous memory sampling (192 MiB total = 49152 pages) */
        { "anon_system_server",  "anon", "system_server",                  8192, 8192 * 4096, 0, 0, "", "" },
        { "anon_surfaceflinger", "anon", "/system/bin/surfaceflinger",     8192, 8192 * 4096, 0, 0, "", "" },
        { "anon_systemui",       "anon", "com.android.systemui",           8192, 8192 * 4096, 0, 0, "", "" },
        { "anon_launcher",       "anon", "com.miui.home",                  8192, 8192 * 4096, 0, 0, "", "" },
        { "anon_ime",            "anon", "com.xiaomi.type",                8192, 8192 * 4096, 0, 0, "", "" },
        { "anon_app",            "anon", "com.android.camera",             8192, 8192 * 4096, 0, 0, "", "" },
        /* Part 2: Real files padding (64 MiB total = 16384 pages) */
        { "file_apk",            "file", "/system/framework/framework.jar", 3072, 3072 * 4096, 0, 0, "", "" },
        { "file_vdex_dex",       "file", "/system/framework/oat/arm64/services.vdex", 3072, 3072 * 4096, 0, 0, "", "" },
        { "file_native_so",      "file", "/apex/com.android.runtime/lib64/bionic/libc.so", 3072, 3072 * 4096, 0, 0, "", "" },
        { "file_sqlite_db",      "file", "/data/user_de/0/com.android.providers.telephony/databases/telephony.db", 2560, 2560 * 4096, 0, 0, "", "" },
        { "file_text_config",    "file", "/data/system/packages.xml",      2048, 2048 * 4096, 0, 0, "", "" },
        { "file_image",          "file", "/product/etc/precust_theme/theme/.data/preview/theme/018f9d39-fdc2-4181-962b-a8f4739dd753/en_US_launcher_0.jpg", 2560, 2560 * 4096, 0, 0, "", "" },
    };
    int num_segments = sizeof(segments) / sizeof(segments[0]);

    uint8_t *page_buf = (uint8_t *)malloc(PAGE_SIZE);
    uint8_t *slice_64p = (uint8_t *)malloc(64 * PAGE_SIZE);

    for (int s = 0; s < num_segments; ++s) {
        segment_info_t *seg = &segments[s];
        fprintf(stderr, "[*] Sampling segment %d/%d: %s (%s, target %zu pages / %zu bytes)\n",
                s + 1, num_segments, seg->category_name, seg->class_type, seg->target_pages, seg->target_bytes);

        SHA256_CTX seg_ctx;
        sha256_init(&seg_ctx);
        size_t collected_pages = 0;
        size_t slice_pages = 0;

        if (strcmp(seg->class_type, "anon") == 0) {
            pid_t pid = find_pid_by_name(seg->target_desc);
            if (pid < 0 && strcmp(seg->category_name, "anon_app") == 0) {
                // Fallback to quicksearchbox if camera not running
                pid = find_pid_by_name("com.android.quicksearchbox");
            }
            if (pid < 0) {
                snprintf(seg->skip_reason, sizeof(seg->skip_reason), "Process not found: %s", seg->target_desc);
                fprintf(stderr, "[-] %s\n", seg->skip_reason);
                continue;
            }

            char mapspath[64], mempath[64];
            snprintf(mapspath, sizeof(mapspath), "/proc/%d/maps", pid);
            snprintf(mempath, sizeof(mempath), "/proc/%d/mem", pid);

            FILE *fmaps = fopen(mapspath, "r");
            int mem_fd = open(mempath, O_RDONLY);
            if (!fmaps || mem_fd < 0) {
                snprintf(seg->skip_reason, sizeof(seg->skip_reason), "Failed to open maps/mem for PID %d: %s", pid, strerror(errno));
                fprintf(stderr, "[-] %s\n", seg->skip_reason);
                if (fmaps) fclose(fmaps);
                if (mem_fd >= 0) close(mem_fd);
                continue;
            }

            char line[1024];
            while (fgets(line, sizeof(line), fmaps) && collected_pages < seg->target_pages) {
                char perms[16] = {0};
                uintptr_t start = 0, end = 0;
                char pathname[512] = {0};
                int parsed = sscanf(line, "%lx-%lx %15s %*s %*s %*s %511s", &start, &end, perms, pathname);
                if (parsed < 3) continue;
                if (strncmp(perms, "rw", 2) != 0) continue;
                // Exclude mapped files (path starts with '/')
                if (pathname[0] == '/') continue;

                // Read pages in this anonymous mapping
                for (uintptr_t addr = start; addr < end && collected_pages < seg->target_pages; addr += PAGE_SIZE) {
                    ssize_t n = pread(mem_fd, page_buf, PAGE_SIZE, (off_t)addr);
                    if (n != PAGE_SIZE) {
                        seg->skipped_pages++;
                        continue;
                    }
                    // Write to combined corpus
                    if (write(out_fd, page_buf, PAGE_SIZE) != PAGE_SIZE) {
                        fprintf(stderr, "[-] Fatal write error to corpus: %s\n", strerror(errno));
                        exit(2);
                    }
                    sha256_update(&seg_ctx, page_buf, PAGE_SIZE);
                    sha256_update(&total_ctx, page_buf, PAGE_SIZE);

                    if (slice_pages < 64) {
                        memcpy(slice_64p + slice_pages * PAGE_SIZE, page_buf, PAGE_SIZE);
                        slice_pages++;
                    }
                    collected_pages++;
                }
            }
            fclose(fmaps);
            close(mem_fd);

            seg->sampled_pages = collected_pages;
            fprintf(stderr, "[+] Anon %s: sampled %zu pages (%zu skipped due to unmapped/non-resident)\n",
                    seg->category_name, collected_pages, seg->skipped_pages);

        } else {
            // Real file sampling
            const char *filepath = seg->target_desc;
            int in_fd = open(filepath, O_RDONLY);
            if (in_fd < 0) {
                snprintf(seg->skip_reason, sizeof(seg->skip_reason), "Failed to open file %s: %s", filepath, strerror(errno));
                fprintf(stderr, "[-] %s\n", seg->skip_reason);
                continue;
            }

            while (collected_pages < seg->target_pages) {
                ssize_t n = read(in_fd, page_buf, PAGE_SIZE);
                if (n < (ssize_t)PAGE_SIZE) {
                    // Rewind to cycle through the real file if smaller than target
                    lseek(in_fd, 0, SEEK_SET);
                    n = read(in_fd, page_buf, PAGE_SIZE);
                    if (n < (ssize_t)PAGE_SIZE) {
                        seg->skipped_pages++;
                        break;
                    }
                }
                if (write(out_fd, page_buf, PAGE_SIZE) != PAGE_SIZE) {
                    fprintf(stderr, "[-] Fatal write error: %s\n", strerror(errno));
                    exit(2);
                }
                sha256_update(&seg_ctx, page_buf, PAGE_SIZE);
                sha256_update(&total_ctx, page_buf, PAGE_SIZE);

                if (slice_pages < 64) {
                    memcpy(slice_64p + slice_pages * PAGE_SIZE, page_buf, PAGE_SIZE);
                    slice_pages++;
                }
                collected_pages++;
            }
            close(in_fd);
            seg->sampled_pages = collected_pages;
            fprintf(stderr, "[+] File %s: sampled %zu pages from %s\n", seg->category_name, collected_pages, filepath);
        }

        uint8_t seg_hash[32];
        sha256_final(&seg_ctx, seg_hash);
        hash_to_hex(seg_hash, seg->sha256_hex);
        fprintf(stderr, "[+] Segment %s SHA-256: %s\n", seg->category_name, seg->sha256_hex);

        // Save 64-page slice for A-group userspace benchmarks
        if (slice_pages == 64) {
            char slice_path[256];
            snprintf(slice_path, sizeof(slice_path), "%s/%s.bin", out_slices_dir, seg->category_name);
            int sfd = open(slice_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (sfd >= 0) {
                write(sfd, slice_64p, 64 * PAGE_SIZE);
                close(sfd);
            }
        }
    }

    close(out_fd);

    uint8_t total_hash[32];
    sha256_final(&total_ctx, total_hash);
    char total_hex[65];
    hash_to_hex(total_hash, total_hex);

    fprintf(stderr, "\n======================================================\n");
    fprintf(stderr, "[*] Real Corpus Generation Complete!\n");
    fprintf(stderr, "[*] Total Size: 268435456 bytes (256 MiB)\n");
    fprintf(stderr, "[*] Total SHA-256: %s\n", total_hex);
    fprintf(stderr, "======================================================\n");

    // Also create real_composite.bin (64 pages sampled proportionally across all 12 segments)
    char comp_slice_path[256];
    snprintf(comp_slice_path, sizeof(comp_slice_path), "%s/real_composite.bin", out_slices_dir);
    int comp_fd = open(comp_slice_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (comp_fd >= 0) {
        int full_fd = open(out_path, O_RDONLY);
        if (full_fd >= 0) {
            // Pick 64 pages spread evenly over the 65536 pages
            for (int p = 0; p < 64; ++p) {
                off_t offset = (off_t)(p * 1024) * PAGE_SIZE; // every 1024 pages (~4 MiB)
                pread(full_fd, page_buf, PAGE_SIZE, offset);
                write(comp_fd, page_buf, PAGE_SIZE);
            }
            close(full_fd);
        }
        close(comp_fd);
    }

    // Write manifest JSON
    FILE *fman = fopen(manifest_path, "w");
    if (fman) {
        fprintf(fman, "{\n");
        fprintf(fman, "  \"total_bytes\": 268435456,\n");
        fprintf(fman, "  \"total_pages\": 65536,\n");
        fprintf(fman, "  \"total_sha256\": \"%s\",\n", total_hex);
        fprintf(fman, "  \"segments\": [\n");
        for (int s = 0; s < num_segments; ++s) {
            segment_info_t *seg = &segments[s];
            fprintf(fman, "    {\n");
            fprintf(fman, "      \"category\": \"%s\",\n", seg->category_name);
            fprintf(fman, "      \"class_type\": \"%s\",\n", seg->class_type);
            fprintf(fman, "      \"target_desc\": \"%s\",\n", seg->target_desc);
            fprintf(fman, "      \"target_bytes\": %zu,\n", seg->target_bytes);
            fprintf(fman, "      \"sampled_pages\": %zu,\n", seg->sampled_pages);
            fprintf(fman, "      \"skipped_pages\": %zu,\n", seg->skipped_pages);
            fprintf(fman, "      \"skip_reason\": \"%s\",\n", seg->skip_reason);
            fprintf(fman, "      \"sha256\": \"%s\"\n", seg->sha256_hex);
            fprintf(fman, "    }%s\n", (s + 1 < num_segments) ? "," : "");
        }
        fprintf(fman, "  ]\n");
        fprintf(fman, "}\n");
        fclose(fman);
    }

    free(page_buf);
    free(slice_64p);
    return 0;
}

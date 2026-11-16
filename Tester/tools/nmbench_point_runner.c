#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sched.h>

#define NOMOUNT_MAGIC_SIG 0x4E4F4D4F554E54ULL

enum {
    NM_CMD_UNSPEC = 0,
    NM_CMD_GET_VERSION,
    NM_CMD_ADD_RULE,
    NM_CMD_DEL_RULE,
    NM_CMD_ADD_UID,
    NM_CMD_DEL_UID,
    NM_CMD_CLEAR_ALL,
    NM_CMD_CLEAR_RULES,
    NM_CMD_CLEAR_UIDS,
    NM_CMD_GET_LIST,
    NM_CMD_GET_UIDS,
    NM_CMD_BLOCK_ISOLATED_UIDS,
    NM_CMD_GET_ISOLATED_STATE,
};

struct nm_payload {
    unsigned long long magic;
    unsigned int cmd;
    unsigned int target_uid;
    int status;
    unsigned int arg1;
    unsigned int data_size;
    char buffer[4068];
} __attribute__((packed));

struct nm_rule_hdr {
    unsigned int flags;
    unsigned int uid;
    unsigned int uid_end;
    unsigned int deny_start;
    unsigned int deny_end;
    unsigned short v_len;
    unsigned short r_len;
} __attribute__((packed));

struct nm_del_hdr {
    unsigned int uid;
    unsigned int uid_end;
    unsigned int deny_start;
    unsigned int deny_end;
    unsigned short v_len;
} __attribute__((packed));

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline int nm_send_payload(struct nm_payload *payload) {
    payload->magic = NOMOUNT_MAGIC_SIG;
    payload->status = -1;
    unsigned long ptr = (unsigned long)payload;
    syscall(SYS_add_key, "nomount", "trigger", &ptr, sizeof(ptr), -1);
    return payload->status;
}

static inline int direct_add_rule(const char *vpath, const char *rpath) {
    struct nm_payload p;
    memset(&p, 0, sizeof(p));
    p.cmd = NM_CMD_ADD_RULE;
    p.arg1 = 0;
    struct nm_rule_hdr *h = (void *)p.buffer;
    h->flags = 0;
    h->uid = 0;
    h->uid_end = 0;
    h->deny_start = 0;
    h->deny_end = 0;
    h->v_len = strlen(vpath);
    h->r_len = strlen(rpath);
    memcpy(p.buffer + sizeof(*h), vpath, h->v_len);
    memcpy(p.buffer + sizeof(*h) + h->v_len, rpath, h->r_len);
    p.data_size = sizeof(*h) + h->v_len + h->r_len;
    return nm_send_payload(&p);
}

static inline int direct_del_rule(const char *vpath) {
    struct nm_payload p;
    memset(&p, 0, sizeof(p));
    p.cmd = NM_CMD_DEL_RULE;
    p.arg1 = 0;
    struct nm_del_hdr *h = (void *)p.buffer;
    h->uid = 0;
    h->uid_end = 0;
    h->deny_start = 0;
    h->deny_end = 0;
    h->v_len = strlen(vpath);
    memcpy(p.buffer + sizeof(*h), vpath, h->v_len);
    p.data_size = sizeof(*h) + h->v_len;
    return nm_send_payload(&p);
}

typedef struct {
    uint64_t min_ns;
    uint64_t max_ns;
    uint64_t p50_ns;
    uint64_t p95_ns;
    uint64_t p99_ns;
    double mean_ns;
    size_t count;
    size_t ok_count;
} stats_t;

static int cmp_u64(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

static stats_t calc_stats(uint64_t *samples, int *statuses, size_t n) {
    stats_t s = {0};
    if (n == 0) return s;
    uint64_t *sorted = malloc(n * sizeof(uint64_t));
    if (!sorted) return s;
    memcpy(sorted, samples, n * sizeof(uint64_t));
    qsort(sorted, n, sizeof(uint64_t), cmp_u64);
    s.min_ns = sorted[0];
    s.max_ns = sorted[n - 1];
    s.p50_ns = sorted[(n * 50) / 100];
    s.p95_ns = sorted[(n * 95) / 100];
    s.p99_ns = sorted[(n * 99) / 100];
    s.count = n;
    double sum = 0;
    size_t ok_cnt = 0;
    for (size_t i = 0; i < n; i++) {
        sum += (double)samples[i];
        if (statuses[i] == 0) ok_cnt++;
    }
    s.mean_ns = sum / (double)n;
    s.ok_count = ok_cnt;
    free(sorted);
    return s;
}

static void print_stats_line(const char *label, stats_t s) {
    printf("%-36s count=%zu ok=%zu (%.1f%%) min=%.2fus p50=%.2fus p95=%.2fus p99=%.2fus max=%.2fus mean=%.2fus\n",
           label, s.count, s.ok_count, (s.count ? (100.0 * s.ok_count / s.count) : 0.0),
           s.min_ns / 1000.0, s.p50_ns / 1000.0,
           s.p95_ns / 1000.0, s.p99_ns / 1000.0,
           s.max_ns / 1000.0, s.mean_ns / 1000.0);
}

static void append_csv(const char *filepath, const char *metric, const char *tier_or_round,
                       uint64_t *samples, int *statuses, size_t n) {
    if (!filepath || !filepath[0]) return;
    FILE *f = fopen(filepath, "a");
    if (!f) return;
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%s,%s,%zu,%llu,%d\n", metric, tier_or_round, i, (unsigned long long)samples[i], statuses[i]);
    }
    fclose(f);
}

/* Setup test environment */
static int do_setup(void) {
    mkdir("/data/local/tmp/nmbench", 0755);
    int fd = open("/data/local/tmp/nmbench/backing_4k.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        char buf[4096];
        memset(buf, 0x5a, sizeof(buf));
        write(fd, buf, sizeof(buf));
        close(fd);
    }
    printf("Setup completed: backing file created.\n");
    return 0;
}

/* Background rule injection/clean */
static int do_inject_bg(int count) {
    const char *rpath = "/data/local/tmp/nmbench/backing_4k.bin";
    char vpath[256];
    int err_cnt = 0;
    for (int i = 1; i <= count; i++) {
        snprintf(vpath, sizeof(vpath), "/system/etc/nmbench_bg/rule_%04d", i);
        int rc = direct_add_rule(vpath, rpath);
        if (rc != 0) err_cnt++;
    }
    printf("Injected %d bg rules (errors: %d)\n", count, err_cnt);
    return err_cnt;
}

static int do_clean_bg(int count) {
    char vpath[256];
    int err_cnt = 0;
    for (int i = 1; i <= count; i++) {
        snprintf(vpath, sizeof(vpath), "/system/etc/nmbench_bg/rule_%04d", i);
        int rc = direct_del_rule(vpath);
        if (rc != 0) err_cnt++;
    }
    printf("Cleaned %d bg rules (errors: %d)\n", count, err_cnt);
    return err_cnt;
}

/*
 * P1: Pure ADD point test
 * Adds 200 rules sequentially, timing each individually.
 * Compares overall, first 50 rules, last 50 rules.
 * Then immediately deletes the 200 rules so no leftovers.
 */
static int do_p1(int scale, const char *csv_path) {
    const int count = 200;
    const char *rpath = "/data/local/tmp/nmbench/backing_4k.bin";
    uint64_t *samples = malloc(count * sizeof(uint64_t));
    int *statuses = malloc(count * sizeof(int));
    if (!samples || !statuses) return 1;

    char vpath[256];
    for (int i = 0; i < count; i++) {
        snprintf(vpath, sizeof(vpath), "/system/etc/nmbench_p1/rule_%04d", i + 1);
        uint64_t t0 = get_time_ns();
        int rc = direct_add_rule(vpath, rpath);
        uint64_t t1 = get_time_ns();
        samples[i] = t1 - t0;
        statuses[i] = rc;
    }

    char tier_str[32];
    snprintf(tier_str, sizeof(tier_str), "%d", scale);

    stats_t s_all = calc_stats(samples, statuses, count);
    stats_t s_first50 = calc_stats(samples, statuses, 50);
    stats_t s_last50 = calc_stats(samples + 150, statuses + 150, 50);

    char label[128];
    snprintf(label, sizeof(label), "P1_ADD_scale%d_all200", scale);
    print_stats_line(label, s_all);
    snprintf(label, sizeof(label), "P1_ADD_scale%d_first50", scale);
    print_stats_line(label, s_first50);
    snprintf(label, sizeof(label), "P1_ADD_scale%d_last50", scale);
    print_stats_line(label, s_last50);

    append_csv(csv_path, "P1_ADD", tier_str, samples, statuses, count);

    /* Clean up the 200 rules added */
    for (int i = 0; i < count; i++) {
        snprintf(vpath, sizeof(vpath), "/system/etc/nmbench_p1/rule_%04d", i + 1);
        direct_del_rule(vpath);
    }

    free(samples);
    free(statuses);
    return 0;
}

/*
 * P2a: Busy DEL point test (Round r)
 * First adds 200 rules.
 * IMMEDIATELY (no delay) sequentially deletes the 200 rules, timing each DEL individually.
 */
static int do_p2a(int round_num, const char *csv_path) {
    const int count = 200;
    const char *rpath = "/data/local/tmp/nmbench/backing_4k.bin";
    uint64_t *samples = malloc(count * sizeof(uint64_t));
    int *statuses = malloc(count * sizeof(int));
    if (!samples || !statuses) return 1;

    char vpath[256];
    /* Pre-add 200 rules */
    for (int i = 0; i < count; i++) {
        snprintf(vpath, sizeof(vpath), "/system/etc/nmbench_p2/rule_%04d", i + 1);
        direct_add_rule(vpath, rpath);
    }

    /* IMMEDIATELY delete all 200 rules without waiting */
    for (int i = 0; i < count; i++) {
        snprintf(vpath, sizeof(vpath), "/system/etc/nmbench_p2/rule_%04d", i + 1);
        uint64_t t0 = get_time_ns();
        int rc = direct_del_rule(vpath);
        uint64_t t1 = get_time_ns();
        samples[i] = t1 - t0;
        statuses[i] = rc;
    }

    char round_str[32];
    snprintf(round_str, sizeof(round_str), "round%d", round_num);

    stats_t s = calc_stats(samples, statuses, count);
    char label[128];
    snprintf(label, sizeof(label), "P2a_DEL_busy_round%d", round_num);
    print_stats_line(label, s);

    append_csv(csv_path, "P2a_DEL_busy", round_str, samples, statuses, count);

    free(samples);
    free(statuses);
    return 0;
}

/*
 * P2b: Idle DEL point test (Round r)
 * First adds 200 rules.
 * WAITS 0.2s (usleep 200000) for retirement workqueue to drain.
 * Then sequentially deletes the 200 rules, timing each DEL individually.
 */
static int do_p2b(int round_num, const char *csv_path) {
    const int count = 200;
    const char *rpath = "/data/local/tmp/nmbench/backing_4k.bin";
    uint64_t *samples = malloc(count * sizeof(uint64_t));
    int *statuses = malloc(count * sizeof(int));
    if (!samples || !statuses) return 1;

    char vpath[256];
    /* Pre-add 200 rules */
    for (int i = 0; i < count; i++) {
        snprintf(vpath, sizeof(vpath), "/system/etc/nmbench_p2/rule_%04d", i + 1);
        direct_add_rule(vpath, rpath);
    }

    /* Wait 0.2s for queue drain */
    usleep(200000);

    /* Delete all 200 rules */
    for (int i = 0; i < count; i++) {
        snprintf(vpath, sizeof(vpath), "/system/etc/nmbench_p2/rule_%04d", i + 1);
        uint64_t t0 = get_time_ns();
        int rc = direct_del_rule(vpath);
        uint64_t t1 = get_time_ns();
        samples[i] = t1 - t0;
        statuses[i] = rc;
    }

    char round_str[32];
    snprintf(round_str, sizeof(round_str), "round%d", round_num);

    stats_t s = calc_stats(samples, statuses, count);
    char label[128];
    snprintf(label, sizeof(label), "P2b_DEL_idle_round%d", round_num);
    print_stats_line(label, s);

    append_csv(csv_path, "P2b_DEL_idle", round_str, samples, statuses, count);

    free(samples);
    free(statuses);
    return 0;
}

/*
 * P3: Scale tier sampling (20 samples of ADD + 20 samples of DEL)
 * At given scale (47, 200, 500).
 * In each sample: ADD probe, wait 0.2s, DEL probe, wait 0.2s.
 */
static int do_p3(int scale, const char *csv_path) {
    const int samples_cnt = 20;
    const char *vprobe = "/system/etc/nmbench_p3/probe";
    const char *rpath = "/data/local/tmp/nmbench/backing_4k.bin";

    uint64_t *add_samples = malloc(samples_cnt * sizeof(uint64_t));
    int *add_statuses = malloc(samples_cnt * sizeof(int));
    uint64_t *del_samples = malloc(samples_cnt * sizeof(uint64_t));
    int *del_statuses = malloc(samples_cnt * sizeof(int));
    if (!add_samples || !add_statuses || !del_samples || !del_statuses) return 1;

    for (int i = 0; i < samples_cnt; i++) {
        uint64_t t0 = get_time_ns();
        int rc_add = direct_add_rule(vprobe, rpath);
        uint64_t t1 = get_time_ns();
        add_samples[i] = t1 - t0;
        add_statuses[i] = rc_add;

        usleep(200000); /* wait 0.2s for queue drain */

        t0 = get_time_ns();
        int rc_del = direct_del_rule(vprobe);
        t1 = get_time_ns();
        del_samples[i] = t1 - t0;
        del_statuses[i] = rc_del;

        usleep(200000); /* wait 0.2s before next sample */
    }

    char tier_str[32];
    snprintf(tier_str, sizeof(tier_str), "%d", scale);

    stats_t s_add = calc_stats(add_samples, add_statuses, samples_cnt);
    stats_t s_del = calc_stats(del_samples, del_statuses, samples_cnt);

    char label[128];
    snprintf(label, sizeof(label), "P3_scale%d_ADD", scale);
    print_stats_line(label, s_add);
    snprintf(label, sizeof(label), "P3_scale%d_DEL", scale);
    print_stats_line(label, s_del);

    append_csv(csv_path, "P3_ADD", tier_str, add_samples, add_statuses, samples_cnt);
    append_csv(csv_path, "P3_DEL", tier_str, del_samples, del_statuses, samples_cnt);

    free(add_samples);
    free(add_statuses);
    free(del_samples);
    free(del_statuses);
    return 0;
}

/*
 * P4: Visibility & Interleaving verification
 * 1) Immediate invisibility after DEL (100 iterations stat + open -> ENOENT).
 * 2) Held FD across DEL and Re-add.
 */
static int do_p4(const char *csv_path) {
    const char *rpath = "/data/local/tmp/nmbench/backing_4k.bin";
    const char *vpath = "/system/etc/nmbench_p4_vis";
    struct stat st;

    printf("\n--- P4 Sub-test 1: Immediate Invisibility on DEL (100 iters) ---\n");
    int vis_fails = 0;
    uint64_t samples[100];
    int statuses[100];

    for (int i = 0; i < 100; i++) {
        direct_add_rule(vpath, rpath);
        if (stat(vpath, &st) != 0) {
            printf("FAIL: stat failed after add in iter %d\n", i);
            vis_fails++;
        }

        uint64_t t0 = get_time_ns();
        int rc_del = direct_del_rule(vpath);
        int rc_stat = stat(vpath, &st);
        int stat_err = errno;
        uint64_t t1 = get_time_ns();

        samples[i] = t1 - t0;
        statuses[i] = rc_del;

        if (rc_del != 0 || rc_stat == 0 || stat_err != ENOENT) {
            printf("FAIL: iter %d: rc_del=%d, rc_stat=%d, errno=%d (%s)\n",
                   i, rc_del, rc_stat, stat_err, strerror(stat_err));
            vis_fails++;
        }

        int fd = open(vpath, O_RDONLY);
        if (fd >= 0) {
            close(fd);
            printf("FAIL: iter %d: open succeeded on deleted rule!\n", i);
            vis_fails++;
        } else if (errno != ENOENT) {
            printf("FAIL: iter %d: open returned errno %d (%s), expected ENOENT\n",
                   i, errno, strerror(errno));
            vis_fails++;
        }
    }

    if (vis_fails == 0) {
        printf("P4 Sub-test 1 PASS: 100/100 immediate ENOENT verified upon DEL completion.\n");
    } else {
        printf("P4 Sub-test 1 FAIL: %d failures observed!\n", vis_fails);
    }
    append_csv(csv_path, "P4_vis_stat_enoent", "100iters", samples, statuses, 100);

    printf("\n--- P4 Sub-test 2: Held FD Lifetime Across DEL and Re-add ---\n");
    const char *b_v1 = "/data/local/tmp/nmbench/backing_p4_v1.txt";
    const char *b_v2 = "/data/local/tmp/nmbench/backing_p4_v2.txt";
    const char *vheld = "/system/etc/nmbench_p4_held";

    int fd1 = open(b_v1, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fd1, "OLD_V1_CONTENT_DATA\n", 20);
    close(fd1);

    int fd2 = open(b_v2, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fd2, "NEW_V2_CONTENT_DATA\n", 20);
    close(fd2);

    int held_rc = 0;
    /* 1. Add v1 rule */
    direct_add_rule(vheld, b_v1);

    /* 2. Open old_fd */
    int old_fd = open(vheld, O_RDONLY);
    if (old_fd < 0) {
        printf("FAIL: open old_fd failed: %s\n", strerror(errno));
        held_rc = 1;
    }
    char obuf[32] = {0};
    if (old_fd >= 0) {
        read(old_fd, obuf, 20);
        if (strcmp(obuf, "OLD_V1_CONTENT_DATA\n") != 0) {
            printf("FAIL: old_fd initial read mismatch: '%s'\n", obuf);
            held_rc = 1;
        }
    }

    /* 3. Delete rule while old_fd is held open */
    direct_del_rule(vheld);

    /* 4. Re-add rule pointing to v2 */
    direct_add_rule(vheld, b_v2);

    /* 5. Open new_fd */
    int new_fd = open(vheld, O_RDONLY);
    if (new_fd < 0) {
        printf("FAIL: open new_fd failed: %s\n", strerror(errno));
        held_rc = 1;
    }
    char nbuf[32] = {0};
    if (new_fd >= 0) {
        read(new_fd, nbuf, 20);
        if (strcmp(nbuf, "NEW_V2_CONTENT_DATA\n") != 0) {
            printf("FAIL: new_fd read mismatch: '%s'\n", nbuf);
            held_rc = 1;
        }
    }

    /* 6. Read old_fd again from start */
    if (old_fd >= 0) {
        lseek(old_fd, 0, SEEK_SET);
        memset(obuf, 0, sizeof(obuf));
        read(old_fd, obuf, 20);
        if (strcmp(obuf, "OLD_V1_CONTENT_DATA\n") != 0) {
            printf("FAIL: old_fd contaminated after re-add: '%s'\n", obuf);
            held_rc = 1;
        }
    }

    /* 7. Close both cleanly */
    if (old_fd >= 0 && close(old_fd) != 0) {
        printf("FAIL: close old_fd failed: %s\n", strerror(errno));
        held_rc = 1;
    }
    if (new_fd >= 0 && close(new_fd) != 0) {
        printf("FAIL: close new_fd failed: %s\n", strerror(errno));
        held_rc = 1;
    }

    /* Clean up rule and files */
    direct_del_rule(vheld);
    unlink(b_v1);
    unlink(b_v2);

    if (held_rc == 0) {
        printf("P4 Sub-test 2 PASS: Held FD retains original content across DEL/RE-ADD, clean close, 0 oops.\n");
    } else {
        printf("P4 Sub-test 2 FAIL!\n");
    }

    return (vis_fails == 0 && held_rc == 0) ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <cmd> [args...]\n", argv[0]);
        printf("Commands:\n");
        printf("  setup\n");
        printf("  inject_bg <count>\n");
        printf("  clean_bg <count>\n");
        printf("  p1 <scale: 47|500> [csv_path]\n");
        printf("  p2a <round: 1..3> [csv_path]\n");
        printf("  p2b <round: 1..3> [csv_path]\n");
        printf("  p3 <scale: 47|200|500> [csv_path]\n");
        printf("  p4 [csv_path]\n");
        return 1;
    }

    /* Pin measurement thread to Core 4 (Gold core) */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(4, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    const char *cmd = argv[1];

    if (strcmp(cmd, "setup") == 0) {
        return do_setup();
    } else if (strcmp(cmd, "inject_bg") == 0) {
        int cnt = (argc > 2) ? atoi(argv[2]) : 0;
        return do_inject_bg(cnt);
    } else if (strcmp(cmd, "clean_bg") == 0) {
        int cnt = (argc > 2) ? atoi(argv[2]) : 0;
        return do_clean_bg(cnt);
    } else if (strcmp(cmd, "p1") == 0) {
        int scale = (argc > 2) ? atoi(argv[2]) : 47;
        const char *csv = (argc > 3) ? argv[3] : "";
        return do_p1(scale, csv);
    } else if (strcmp(cmd, "p2a") == 0) {
        int r = (argc > 2) ? atoi(argv[2]) : 1;
        const char *csv = (argc > 3) ? argv[3] : "";
        return do_p2a(r, csv);
    } else if (strcmp(cmd, "p2b") == 0) {
        int r = (argc > 2) ? atoi(argv[2]) : 1;
        const char *csv = (argc > 3) ? argv[3] : "";
        return do_p2b(r, csv);
    } else if (strcmp(cmd, "p3") == 0) {
        int scale = (argc > 2) ? atoi(argv[2]) : 47;
        const char *csv = (argc > 3) ? argv[3] : "";
        return do_p3(scale, csv);
    } else if (strcmp(cmd, "p4") == 0) {
        const char *csv = (argc > 2) ? argv[2] : "";
        return do_p4(csv);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        return 1;
    }
}

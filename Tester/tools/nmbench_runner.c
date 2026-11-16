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
#include <sys/wait.h>
#include <sys/syscall.h>
#include <pthread.h>
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

typedef struct {
    uint64_t min_ns;
    uint64_t max_ns;
    uint64_t p50_ns;
    uint64_t p95_ns;
    uint64_t p99_ns;
    double mean_ns;
    size_t count;
} stats_t;

static int cmp_u64(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

static stats_t calc_stats(uint64_t *samples, size_t n) {
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
    for (size_t i = 0; i < n; i++) sum += (double)sorted[i];
    s.mean_ns = sum / (double)n;
    free(sorted);
    return s;
}

static void print_stats_line(const char *label, stats_t s) {
    printf("%-36s count=%zu min=%.2fus p50=%.2fus p95=%.2fus p99=%.2fus max=%.2fus mean=%.2fus\n",
           label, s.count,
           s.min_ns / 1000.0, s.p50_ns / 1000.0,
           s.p95_ns / 1000.0, s.p99_ns / 1000.0,
           s.max_ns / 1000.0, s.mean_ns / 1000.0);
}

static void dump_csv(const char *filepath, const char *metric, int round, uint64_t *samples, size_t n) {
    FILE *f = fopen(filepath, "a");
    if (!f) return;
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%s,%d,%zu,%llu\n", metric, round, i, (unsigned long long)samples[i]);
    }
    fclose(f);
}

/* Background reader workload */
static volatile bool g_stop_load = false;
static void *read_load_thread(void *arg) {
    const char *vpath = (const char *)arg;
    char buf[4096];
    struct stat st;
    while (!g_stop_load) {
        int fd = open(vpath, O_RDONLY);
        if (fd >= 0) {
            read(fd, buf, sizeof(buf));
            close(fd);
        }
        stat(vpath, &st);
        stat("/system/etc/nmbench_b_rule_0001", &st);
        stat("/system/bin/adb", &st);
        stat("/system/priv-app/MotifyMessages/MotifyMessages.apk", &st);
    }
    return NULL;
}

/* --- Section A Runner --- */
static int run_bench_a(int round, int samples, const char *csv_path) {
    const char *vpath = "/system/etc/nmbench_a_file";
    const char *rpath = "/data/local/tmp/nmbench/backing_4k.bin";

    uint64_t *arr = malloc(samples * sizeof(uint64_t));
    if (!arr) { fprintf(stderr, "malloc failed\n"); return 1; }

    char buf[4096];
    struct stat st;

    /* A1: Virtual open+read+close */
    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        int fd = open(vpath, O_RDONLY);
        if (fd >= 0) {
            read(fd, buf, sizeof(buf));
            close(fd);
        }
        uint64_t t1 = get_time_ns();
        arr[i] = t1 - t0;
    }
    stats_t s_a1_orc = calc_stats(arr, samples);
    print_stats_line("A1_virtual_open_read_close", s_a1_orc);
    if (csv_path) dump_csv(csv_path, "A1_virtual_open_read_close", round, arr, samples);

    /* A1: Virtual stat */
    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        stat(vpath, &st);
        uint64_t t1 = get_time_ns();
        arr[i] = t1 - t0;
    }
    stats_t s_a1_stat = calc_stats(arr, samples);
    print_stats_line("A1_virtual_stat", s_a1_stat);
    if (csv_path) dump_csv(csv_path, "A1_virtual_stat", round, arr, samples);

    /* A2: Real backing open+read+close (control) */
    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        int fd = open(rpath, O_RDONLY);
        if (fd >= 0) {
            read(fd, buf, sizeof(buf));
            close(fd);
        }
        uint64_t t1 = get_time_ns();
        arr[i] = t1 - t0;
    }
    stats_t s_a2_orc = calc_stats(arr, samples);
    print_stats_line("A2_real_open_read_close", s_a2_orc);
    if (csv_path) dump_csv(csv_path, "A2_real_open_read_close", round, arr, samples);

    /* A2: Real stat (control) */
    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        stat(rpath, &st);
        uint64_t t1 = get_time_ns();
        arr[i] = t1 - t0;
    }
    stats_t s_a2_stat = calc_stats(arr, samples);
    print_stats_line("A2_real_stat", s_a2_stat);
    if (csv_path) dump_csv(csv_path, "A2_real_stat", round, arr, samples);

    /* A3: Repeat open accumulate virtual (keep fds open) */
    int *fds = malloc(samples * sizeof(int));
    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        fds[i] = open(vpath, O_RDONLY);
        uint64_t t1 = get_time_ns();
        arr[i] = t1 - t0;
    }
    for (int i = 0; i < samples; i++) {
        if (fds[i] >= 0) close(fds[i]);
    }
    stats_t s_a3_acc_v = calc_stats(arr, samples);
    print_stats_line("A3_accumulate_virtual_open", s_a3_acc_v);
    if (csv_path) dump_csv(csv_path, "A3_accumulate_virtual_open", round, arr, samples);

    /* A3: Repeat open immediate close virtual */
    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        int fd = open(vpath, O_RDONLY);
        uint64_t t1 = get_time_ns();
        if (fd >= 0) close(fd);
        arr[i] = t1 - t0;
    }
    stats_t s_a3_imm_v = calc_stats(arr, samples);
    print_stats_line("A3_immediate_virtual_open", s_a3_imm_v);
    if (csv_path) dump_csv(csv_path, "A3_immediate_virtual_open", round, arr, samples);

    /* A3: Repeat open accumulate real (control) */
    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        fds[i] = open(rpath, O_RDONLY);
        uint64_t t1 = get_time_ns();
        arr[i] = t1 - t0;
    }
    for (int i = 0; i < samples; i++) {
        if (fds[i] >= 0) close(fds[i]);
    }
    stats_t s_a3_acc_r = calc_stats(arr, samples);
    print_stats_line("A3_accumulate_real_open", s_a3_acc_r);
    if (csv_path) dump_csv(csv_path, "A3_accumulate_real_open", round, arr, samples);

    /* A3: Repeat open immediate close real (control) */
    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        int fd = open(rpath, O_RDONLY);
        uint64_t t1 = get_time_ns();
        if (fd >= 0) close(fd);
        arr[i] = t1 - t0;
    }
    stats_t s_a3_imm_r = calc_stats(arr, samples);
    print_stats_line("A3_immediate_real_open", s_a3_imm_r);
    if (csv_path) dump_csv(csv_path, "A3_immediate_real_open", round, arr, samples);

    free(fds);
    free(arr);
    return 0;
}

/* --- Section B Runner --- */
static int run_bench_b(int round, int samples, const char *tier, const char *csv_path) {
    const char *hit_path = "/system/etc/nmbench_b_rule_0001";
    const char *miss_same_path = "/system/etc/nmbench_b_rule_nonexistent";
    const char *miss_unrel_path = "/vendor/etc/nmbench_unrelated_nonexistent";

    uint64_t *arr = malloc(samples * sizeof(uint64_t));
    if (!arr) return 1;
    struct stat st;

    char label[128];

    /* B1: Hit */
    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        stat(hit_path, &st);
        uint64_t t1 = get_time_ns();
        arr[i] = t1 - t0;
    }
    snprintf(label, sizeof(label), "B1_hit_%s", tier);
    stats_t s_b1 = calc_stats(arr, samples);
    print_stats_line(label, s_b1);
    if (csv_path) dump_csv(csv_path, label, round, arr, samples);

    /* B2: Miss same prefix */
    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        stat(miss_same_path, &st);
        uint64_t t1 = get_time_ns();
        arr[i] = t1 - t0;
    }
    snprintf(label, sizeof(label), "B2_miss_same_prefix_%s", tier);
    stats_t s_b2 = calc_stats(arr, samples);
    print_stats_line(label, s_b2);
    if (csv_path) dump_csv(csv_path, label, round, arr, samples);

    /* B3: Miss unrelated prefix */
    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        stat(miss_unrel_path, &st);
        uint64_t t1 = get_time_ns();
        arr[i] = t1 - t0;
    }
    snprintf(label, sizeof(label), "B3_miss_unrelated_%s", tier);
    stats_t s_b3 = calc_stats(arr, samples);
    print_stats_line(label, s_b3);
    if (csv_path) dump_csv(csv_path, label, round, arr, samples);

    free(arr);
    return 0;
}

/* --- Section B Dir Lookup Runner --- */
static int run_bench_b_dir(int round, int samples, int entries, const char *target_path, const char *csv_path) {
    uint64_t *arr = malloc(samples * sizeof(uint64_t));
    if (!arr) return 1;
    struct stat st;

    for (int i = 0; i < samples; i++) {
        uint64_t t0 = get_time_ns();
        stat(target_path, &st);
        uint64_t t1 = get_time_ns();
        arr[i] = t1 - t0;
    }
    char label[128];
    snprintf(label, sizeof(label), "B_dir_lookup_%d_entries", entries);
    stats_t s = calc_stats(arr, samples);
    print_stats_line(label, s);
    if (csv_path) dump_csv(csv_path, label, round, arr, samples);

    free(arr);
    return 0;
}

/* --- Section C Runner --- */
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

static int run_bench_c(int round, int samples, int tier_rules, int read_load, const char *csv_path) {
    const char *vprobe = "/system/etc/nmbench_c_probe";
    const char *rbacking = "/data/local/tmp/nmbench/backing_4k.bin";
    const char *nm_bin = "/data/adb/ap/bin/nm";

    pthread_t bg_threads[4];
    if (read_load) {
        g_stop_load = false;
        for (int i = 0; i < 4; i++) {
            pthread_create(&bg_threads[i], NULL, read_load_thread, (void *)"/system/bin/adb");
        }
    }

    uint64_t *arr_cli_add = malloc(samples * sizeof(uint64_t));
    uint64_t *arr_cli_del = malloc(samples * sizeof(uint64_t));
    uint64_t *arr_sys_add = malloc(samples * sizeof(uint64_t));
    uint64_t *arr_sys_del = malloc(samples * sizeof(uint64_t));
    uint64_t *arr_vis_lag = malloc(samples * sizeof(uint64_t));

    char *const add_argv[] = {(char *)nm_bin, "rule", "add", (char *)vprobe, (char *)rbacking, NULL};
    char *const del_argv[] = {(char *)nm_bin, "rule", "del", (char *)vprobe, NULL};

    struct stat st;

    for (int i = 0; i < samples; i++) {
        /* CLI add */
        uint64_t t0 = get_time_ns();
        pid_t pid = fork();
        if (pid == 0) {
            int nullfd = open("/dev/null", O_WRONLY);
            if (nullfd >= 0) {
                dup2(nullfd, STDOUT_FILENO);
                dup2(nullfd, STDERR_FILENO);
                close(nullfd);
            }
            execve(nm_bin, add_argv, environ);
            _exit(127);
        }
        int status;
        waitpid(pid, &status, 0);
        uint64_t t1 = get_time_ns();
        arr_cli_add[i] = t1 - t0;

        /* Visibility polling lag right after add */
        uint64_t t_vis_start = t1;
        uint64_t t_vis_end = t1;
        int attempts = 0;
        while (1) {
            attempts++;
            if (stat(vprobe, &st) == 0) {
                t_vis_end = get_time_ns();
                break;
            }
            if (get_time_ns() - t_vis_start > 1000000000ULL) break; /* 1s timeout */
        }
        (void)attempts;
        arr_vis_lag[i] = t_vis_end - t_vis_start;

        /* CLI del */
        t0 = get_time_ns();
        pid = fork();
        if (pid == 0) {
            int nullfd = open("/dev/null", O_WRONLY);
            if (nullfd >= 0) {
                dup2(nullfd, STDOUT_FILENO);
                dup2(nullfd, STDERR_FILENO);
                close(nullfd);
            }
            execve(nm_bin, del_argv, environ);
            _exit(127);
        }
        waitpid(pid, &status, 0);
        t1 = get_time_ns();
        arr_cli_del[i] = t1 - t0;

        /* Syscall add */
        t0 = get_time_ns();
        direct_add_rule(vprobe, rbacking);
        t1 = get_time_ns();
        arr_sys_add[i] = t1 - t0;

        /* Syscall del */
        t0 = get_time_ns();
        direct_del_rule(vprobe);
        t1 = get_time_ns();
        arr_sys_del[i] = t1 - t0;
    }

    if (read_load) {
        g_stop_load = true;
        for (int i = 0; i < 4; i++) {
            pthread_join(bg_threads[i], NULL);
        }
    }

    char suffix[64];
    snprintf(suffix, sizeof(suffix), "r%d_%s", tier_rules, read_load ? "load" : "idle");

    char label[128];

    snprintf(label, sizeof(label), "C_cli_add_%s", suffix);
    stats_t s_cli_add = calc_stats(arr_cli_add, samples);
    print_stats_line(label, s_cli_add);
    if (csv_path) dump_csv(csv_path, label, round, arr_cli_add, samples);

    snprintf(label, sizeof(label), "C_cli_del_%s", suffix);
    stats_t s_cli_del = calc_stats(arr_cli_del, samples);
    print_stats_line(label, s_cli_del);
    if (csv_path) dump_csv(csv_path, label, round, arr_cli_del, samples);

    snprintf(label, sizeof(label), "C_sys_add_%s", suffix);
    stats_t s_sys_add = calc_stats(arr_sys_add, samples);
    print_stats_line(label, s_sys_add);
    if (csv_path) dump_csv(csv_path, label, round, arr_sys_add, samples);

    snprintf(label, sizeof(label), "C_sys_del_%s", suffix);
    stats_t s_sys_del = calc_stats(arr_sys_del, samples);
    print_stats_line(label, s_sys_del);
    if (csv_path) dump_csv(csv_path, label, round, arr_sys_del, samples);

    snprintf(label, sizeof(label), "C_visibility_lag_%s", suffix);
    stats_t s_vis = calc_stats(arr_vis_lag, samples);
    print_stats_line(label, s_vis);
    if (csv_path) dump_csv(csv_path, label, round, arr_vis_lag, samples);

    free(arr_cli_add);
    free(arr_cli_del);
    free(arr_sys_add);
    free(arr_sys_del);
    free(arr_vis_lag);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <bench_a|bench_b|bench_b_dir|bench_c|setup> [args...]\n", argv[0]);
        return 1;
    }

    /* Pin measurement thread to Core 4 (Gold core) for reproducibility */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(4, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    if (strcmp(argv[1], "setup") == 0) {
        mkdir("/data/local/tmp/nmbench", 0755);
        int fd = open("/data/local/tmp/nmbench/backing_4k.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            char buf[4096];
            memset(buf, 0x5a, sizeof(buf));
            write(fd, buf, sizeof(buf));
            close(fd);
        }
        printf("setup completed\n");
        return 0;
    }

    if (strcmp(argv[1], "bench_a") == 0) {
        int round = 1;
        int samples = 1000;
        const char *csv = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--round") == 0 && i + 1 < argc) round = atoi(argv[++i]);
            else if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc) samples = atoi(argv[++i]);
            else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) csv = argv[++i];
        }
        return run_bench_a(round, samples, csv);
    }

    if (strcmp(argv[1], "bench_b") == 0) {
        int round = 1;
        int samples = 1000;
        const char *tier = "50";
        const char *csv = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--round") == 0 && i + 1 < argc) round = atoi(argv[++i]);
            else if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc) samples = atoi(argv[++i]);
            else if (strcmp(argv[i], "--tier") == 0 && i + 1 < argc) tier = argv[++i];
            else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) csv = argv[++i];
        }
        return run_bench_b(round, samples, tier, csv);
    }

    if (strcmp(argv[1], "bench_b_dir") == 0) {
        int round = 1;
        int samples = 1000;
        int entries = 10;
        const char *target = "/system/etc/nmbench_dir/entry_0005";
        const char *csv = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--round") == 0 && i + 1 < argc) round = atoi(argv[++i]);
            else if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc) samples = atoi(argv[++i]);
            else if (strcmp(argv[i], "--entries") == 0 && i + 1 < argc) entries = atoi(argv[++i]);
            else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target = argv[++i];
            else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) csv = argv[++i];
        }
        return run_bench_b_dir(round, samples, entries, target, csv);
    }

    if (strcmp(argv[1], "bench_c") == 0) {
        int round = 1;
        int samples = 1000;
        int tier = 47;
        int load = 0;
        const char *csv = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--round") == 0 && i + 1 < argc) round = atoi(argv[++i]);
            else if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc) samples = atoi(argv[++i]);
            else if (strcmp(argv[i], "--tier") == 0 && i + 1 < argc) tier = atoi(argv[++i]);
            else if (strcmp(argv[i], "--read-load") == 0 && i + 1 < argc) load = atoi(argv[++i]);
            else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) csv = argv[++i];
        }
        return run_bench_c(round, samples, tier, load, csv);
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
}

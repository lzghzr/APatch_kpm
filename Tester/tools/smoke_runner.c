#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>

#define WORK_DIR "/data/local/tmp/nmbench_smoke"
#define LOG_PREFIX "[SMOKE]"

static int run_cmd(const char *cmd) {
    return system(cmd);
}

static int get_rule_count(void) {
    FILE *fp = popen("/data/adb/ap/bin/nm rule list | wc -l", "r");
    if (!fp) return -1;
    char buf[64] = {0};
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    return atoi(buf);
}

/* 1. 文件内容与截断完整性 */
static int test1_content_and_truncate(void) {
    printf("%s --- Test 1: Content & Truncate Integrity (§5.3.1) ---\n", LOG_PREFIX);
    int rc = 0;
    char b1_ro[256], b1_rw[256];
    snprintf(b1_ro, sizeof(b1_ro), "%s/backing1_ro.bin", WORK_DIR);
    snprintf(b1_rw, sizeof(b1_rw), "%s/backing1_rw.bin", WORK_DIR);

    // 1A. Read-only content integrity under /system/etc/nmbench_smoke_1
    int fd_ro = open(b1_ro, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd_ro < 0) { perror("open b1_ro"); return 1; }
    char buf[8192];
    for (int i = 0; i < 8192; i++) buf[i] = (char)((i * 37 + 13) & 0xff);
    write(fd_ro, buf, sizeof(buf));
    close(fd_ro);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "/data/adb/ap/bin/nm rule add /system/etc/nmbench_smoke_1 %s", b1_ro);
    if (run_cmd(cmd) != 0) { printf("Failed to add /system/etc/nmbench_smoke_1\n"); return 1; }

    // Multi-read test (10 times)
    for (int iter = 0; iter < 10; iter++) {
        int vfd = open("/system/etc/nmbench_smoke_1", O_RDONLY);
        if (vfd < 0) { printf("iter %d: open failed\n", iter); rc = 1; break; }
        char rbuf[8192];
        ssize_t n = read(vfd, rbuf, sizeof(rbuf));
        close(vfd);
        if (n != 8192 || memcmp(buf, rbuf, 8192) != 0) {
            printf("iter %d: content mismatch\n", iter);
            rc = 1; break;
        }
    }

    // Verify outer-ro boundary: opening /system/etc/nmbench_smoke_1 with O_RDWR should return EROFS
    int ro_vfd = open("/system/etc/nmbench_smoke_1", O_RDWR);
    if (ro_vfd >= 0) {
        close(ro_vfd);
        printf("FAIL: Expected EROFS on outer-ro /system mount, but open succeeded!\n");
        rc = 1;
    } else if (errno != EROFS) {
        printf("FAIL: Expected EROFS, got errno %d (%s)\n", errno, strerror(errno));
        rc = 1;
    }

    run_cmd("/data/adb/ap/bin/nm rule del /system/etc/nmbench_smoke_1");
    if (rc != 0) return rc;

    // 1B. Writable mount truncate/append integrity under /data/local/tmp/nmbench_smoke_1_rw
    int fd_rw = open(b1_rw, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd_rw < 0) { perror("open b1_rw"); return 1; }
    const char *initial = "INITIAL_DATA_8192_REPRESENTATION_FOR_TRUNCATE_APPEND_TEST";
    write(fd_rw, initial, strlen(initial));
    close(fd_rw);

    snprintf(cmd, sizeof(cmd), "/data/adb/ap/bin/nm rule add /data/local/tmp/nmbench_smoke_1_rw %s", b1_rw);
    if (run_cmd(cmd) != 0) { printf("Failed to add /data/local/tmp/nmbench_smoke_1_rw\n"); return 1; }

    // O_TRUNC test
    int tfd = open("/data/local/tmp/nmbench_smoke_1_rw", O_RDWR | O_TRUNC);
    if (tfd < 0) { perror("open O_TRUNC"); run_cmd("/data/adb/ap/bin/nm rule del /data/local/tmp/nmbench_smoke_1_rw"); return 1; }
    const char *tdata = "TRUNCATED_50_BYTES_OF_DATA_FOR_TESTING_PURPOSES!!\n";
    size_t tlen = strlen(tdata);
    if (write(tfd, tdata, tlen) != (ssize_t)tlen) { close(tfd); rc = 1; }
    close(tfd);

    struct stat st_v, st_b;
    if (stat("/data/local/tmp/nmbench_smoke_1_rw", &st_v) != 0 || stat(b1_rw, &st_b) != 0) { rc = 1; }
    if (st_v.st_size != (off_t)tlen || st_b.st_size != (off_t)tlen) {
        printf("Size mismatch after O_TRUNC: v=%lld, b=%lld, expected=%zu\n", (long long)st_v.st_size, (long long)st_b.st_size, tlen);
        rc = 1;
    }

    // O_APPEND test
    int afd = open("/data/local/tmp/nmbench_smoke_1_rw", O_RDWR | O_APPEND);
    if (afd < 0) { perror("open O_APPEND"); rc = 1; }
    const char *adata = "APPENDED_32_BYTES_OF_DATA_12345\n";
    size_t alen = strlen(adata);
    if (write(afd, adata, alen) != (ssize_t)alen) { close(afd); rc = 1; }
    close(afd);

    if (stat("/data/local/tmp/nmbench_smoke_1_rw", &st_v) != 0 || stat(b1_rw, &st_b) != 0) { rc = 1; }
    if (st_v.st_size != (off_t)(tlen + alen) || st_b.st_size != (off_t)(tlen + alen)) {
        printf("Size mismatch after O_APPEND: v=%lld, b=%lld, expected=%zu\n", (long long)st_v.st_size, (long long)st_b.st_size, tlen + alen);
        rc = 1;
    }

    // Read back and verify full content
    int rfd = open("/data/local/tmp/nmbench_smoke_1_rw", O_RDONLY);
    char full_buf[128] = {0};
    read(rfd, full_buf, sizeof(full_buf) - 1);
    close(rfd);
    char expected_buf[128];
    snprintf(expected_buf, sizeof(expected_buf), "%s%s", tdata, adata);
    if (strcmp(full_buf, expected_buf) != 0) {
        printf("Content mismatch after append: '%s' vs '%s'\n", full_buf, expected_buf);
        rc = 1;
    }

    run_cmd("/data/adb/ap/bin/nm rule del /data/local/tmp/nmbench_smoke_1_rw");
    if (rc == 0) {
        printf("%s Test 1 PASS: Content matches across multiple reads, O_TRUNC and O_APPEND accurately reflected\n", LOG_PREFIX);
    }
    return rc;
}

/* 2. 多 FD 独立位置隔离 */
struct thread_arg {
    int fd;
    off_t start_offset;
    size_t length;
    int err;
};

static void *read_worker(void *p) {
    struct thread_arg *a = (struct thread_arg *)p;
    char *buf = malloc(a->length);
    if (!buf) { a->err = 1; return NULL; }
    
    size_t total = 0;
    while (total < a->length) {
        size_t chunk = (a->length - total > 64) ? 64 : (a->length - total);
        ssize_t n = read(a->fd, buf + total, chunk);
        if (n <= 0) { a->err = 2; free(buf); return NULL; }
        total += n;
    }
    
    for (size_t i = 0; i < a->length; i++) {
        char expected = (char)((a->start_offset + i) % 251);
        if (buf[i] != expected) {
            a->err = 3;
            free(buf);
            return NULL;
        }
    }
    free(buf);
    a->err = 0;
    return NULL;
}

static int test2_multi_fd_isolation(void) {
    printf("%s --- Test 2: Multi-FD Concurrency & Position Isolation (§5.3.2) ---\n", LOG_PREFIX);
    char backing[256];
    snprintf(backing, sizeof(backing), "%s/backing2.bin", WORK_DIR);

    int bfd = open(backing, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (bfd < 0) return 1;
    char buf[4096];
    for (int i = 0; i < 4096; i++) buf[i] = (char)(i % 251);
    write(bfd, buf, sizeof(buf));
    close(bfd);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "/data/adb/ap/bin/nm rule add /system/etc/nmbench_smoke_2 %s", backing);
    if (run_cmd(cmd) != 0) return 1;

    int fd1 = open("/system/etc/nmbench_smoke_2", O_RDONLY);
    int fd2 = open("/system/etc/nmbench_smoke_2", O_RDONLY);
    if (fd1 < 0 || fd2 < 0 || fd1 == fd2) {
        run_cmd("/data/adb/ap/bin/nm rule del /system/etc/nmbench_smoke_2");
        return 1;
    }

    // lseek fd1 to 1024
    if (lseek(fd1, 1024, SEEK_SET) != 1024) { close(fd1); close(fd2); return 1; }
    // verify fd2 is still at 0
    if (lseek(fd2, 0, SEEK_CUR) != 0) {
        printf("FAIL: fd2 position contaminated by fd1 seek: %lld\n", (long long)lseek(fd2, 0, SEEK_CUR));
        close(fd1); close(fd2); return 1;
    }

    // Read 32 bytes from fd2
    char r2[32];
    if (read(fd2, r2, 32) != 32) { close(fd1); close(fd2); return 1; }
    for (int i = 0; i < 32; i++) {
        if (r2[i] != (char)(i % 251)) { close(fd1); close(fd2); return 1; }
    }
    if (lseek(fd2, 0, SEEK_CUR) != 32) { close(fd1); close(fd2); return 1; }
    if (lseek(fd1, 0, SEEK_CUR) != 1024) { close(fd1); close(fd2); return 1; }

    // Read 32 bytes from fd1
    char r1[32];
    if (read(fd1, r1, 32) != 32) { close(fd1); close(fd2); return 1; }
    for (int i = 0; i < 32; i++) {
        if (r1[i] != (char)((1024 + i) % 251)) { close(fd1); close(fd2); return 1; }
    }
    if (lseek(fd1, 0, SEEK_CUR) != 1056) { close(fd1); close(fd2); return 1; }

    // Concurrently read via pthreads
    pthread_t t1, t2;
    struct thread_arg arg1 = {.fd = fd1, .start_offset = 1056, .length = 1024, .err = 0};
    struct thread_arg arg2 = {.fd = fd2, .start_offset = 32, .length = 1024, .err = 0};
    pthread_create(&t1, NULL, read_worker, &arg1);
    pthread_create(&t2, NULL, read_worker, &arg2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    close(fd1);
    close(fd2);
    run_cmd("/data/adb/ap/bin/nm rule del /system/etc/nmbench_smoke_2");

    if (arg1.err != 0 || arg2.err != 0) {
        printf("FAIL: Concurrent read error: arg1=%d, arg2=%d\n", arg1.err, arg2.err);
        return 1;
    }

    printf("%s Test 2 PASS: Multi-FD positions completely independent, concurrency safe\n", LOG_PREFIX);
    return 0;
}

/* 3. UID 策略与权限隔离 */
static int test3_uid_policy(void) {
    printf("%s --- Test 3: UID Policy & Security Isolation (§5.3.3) ---\n", LOG_PREFIX);
    char backing[256];
    snprintf(backing, sizeof(backing), "%s/backing3.txt", WORK_DIR);

    int bfd = open(backing, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (bfd < 0) return 1;
    const char *val = "UID_NON_EXCLUDED_VALUE\n";
    write(bfd, val, strlen(val));
    close(bfd);

    // Rule excluding UIDs 2000-3000
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "/data/adb/ap/bin/nm rule add --uid-excluded 2000-3000 /system/etc/nmbench_smoke_3 %s", backing);
    if (run_cmd(cmd) != 0) return 1;

    // As root (UID 0): should see virtual file
    int fd_root = open("/system/etc/nmbench_smoke_3", O_RDONLY);
    if (fd_root < 0) { printf("root failed to open /system/etc/nmbench_smoke_3\n"); return 1; }
    char r_val[64] = {0};
    read(fd_root, r_val, sizeof(r_val) - 1);
    close(fd_root);
    if (strcmp(r_val, val) != 0) { printf("root got unexpected value: %s\n", r_val); return 1; }

    // As UID 2500 (in excluded range): should pass through to native FS -> ENOENT
    pid_t pid = fork();
    if (pid == 0) {
        if (setuid(2500) != 0) exit(10);
        int fd_ex = open("/system/etc/nmbench_smoke_3", O_RDONLY);
        if (fd_ex >= 0) {
            close(fd_ex);
            exit(1); // Should have been ENOENT
        }
        if (errno == ENOENT) exit(0);
        exit(2);
    }
    int status;
    waitpid(pid, &status, 0);
    run_cmd("/data/adb/ap/bin/nm rule del --uid-excluded 2000-3000 /system/etc/nmbench_smoke_3");

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("FAIL: Excluded UID check failed: child exit code %d\n", WEXITSTATUS(status));
        return 1;
    }

    printf("%s Test 3 PASS: Excluded UIDs direct pass-through, regular UIDs redirected\n", LOG_PREFIX);
    return 0;
}

/* 4. 删除即时可见性 */
static int test4_immediate_invisibility(void) {
    printf("%s --- Test 4: Immediate Invisibility on DEL/CLEAR (§5.3.4) ---\n", LOG_PREFIX);
    char backing[256];
    snprintf(backing, sizeof(backing), "%s/backing4.bin", WORK_DIR);

    int bfd = open(backing, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (bfd < 0) return 1;
    write(bfd, "DATA4", 5);
    close(bfd);

    char add_cmd[512], del_cmd[512];
    snprintf(add_cmd, sizeof(add_cmd), "/data/adb/ap/bin/nm rule add /system/etc/nmbench_smoke_4 %s", backing);
    snprintf(del_cmd, sizeof(del_cmd), "/data/adb/ap/bin/nm rule del /system/etc/nmbench_smoke_4");

    for (int iter = 0; iter < 100; iter++) {
        if (run_cmd(add_cmd) != 0) { printf("add failed at iter %d\n", iter); return 1; }
        
        // Check exists
        struct stat st;
        if (stat("/system/etc/nmbench_smoke_4", &st) != 0) { printf("stat failed after add iter %d\n", iter); return 1; }

        // DEL rule
        if (run_cmd(del_cmd) != 0) { printf("del failed at iter %d\n", iter); return 1; }

        // IMMEDIATELY stat / open
        int rc = stat("/system/etc/nmbench_smoke_4", &st);
        if (rc == 0) {
            printf("FAIL: Stale virtual file visible after DEL! iter %d\n", iter);
            return 1;
        }
        int fd = open("/system/etc/nmbench_smoke_4", O_RDONLY);
        if (fd >= 0) {
            close(fd);
            printf("FAIL: Stale virtual file opened after DEL! iter %d\n", iter);
            return 1;
        }
        if (errno != ENOENT) {
            printf("FAIL: Unexpected errno after DEL: %d (%s)\n", errno, strerror(errno));
            return 1;
        }
    }

    printf("%s Test 4 PASS: 100/100 immediate ENOENT verified upon DEL completion\n", LOG_PREFIX);
    return 0;
}

/* 5. 重加规则与旧 FD 保活交错 */
static int test5_readd_held_fd(void) {
    printf("%s --- Test 5: Re-add & Active FD Lifetime (§5.3.5) ---\n", LOG_PREFIX);
    char backing_v1[256], backing_v2[256];
    snprintf(backing_v1, sizeof(backing_v1), "%s/backing5_v1.txt", WORK_DIR);
    snprintf(backing_v2, sizeof(backing_v2), "%s/backing5_v2.txt", WORK_DIR);

    int b1 = open(backing_v1, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    write(b1, "OLD_V1_CONTENT_DATA\n", 20);
    close(b1);

    int b2 = open(backing_v2, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    write(b2, "NEW_V2_CONTENT_DATA\n", 20);
    close(b2);

    // 1. Add v1 rule
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "/data/adb/ap/bin/nm rule add /system/etc/nmbench_smoke_5 %s", backing_v1);
    if (run_cmd(cmd) != 0) return 1;

    // 2. Open old_fd
    int old_fd = open("/system/etc/nmbench_smoke_5", O_RDONLY);
    if (old_fd < 0) return 1;
    char obuf[32] = {0};
    read(old_fd, obuf, 20);
    if (strcmp(obuf, "OLD_V1_CONTENT_DATA\n") != 0) { close(old_fd); return 1; }

    // 3. Delete rule while old_fd is held open
    run_cmd("/data/adb/ap/bin/nm rule del /system/etc/nmbench_smoke_5");

    // 4. Re-add rule pointing to v2
    snprintf(cmd, sizeof(cmd), "/data/adb/ap/bin/nm rule add /system/etc/nmbench_smoke_5 %s", backing_v2);
    if (run_cmd(cmd) != 0) { close(old_fd); return 1; }

    // 5. Open new_fd
    int new_fd = open("/system/etc/nmbench_smoke_5", O_RDONLY);
    if (new_fd < 0) { close(old_fd); return 1; }
    char nbuf[32] = {0};
    read(new_fd, nbuf, 20);
    if (strcmp(nbuf, "NEW_V2_CONTENT_DATA\n") != 0) {
        printf("FAIL: new_fd content unexpected: %s\n", nbuf);
        close(old_fd); close(new_fd); return 1;
    }

    // 6. Read old_fd again
    lseek(old_fd, 0, SEEK_SET);
    memset(obuf, 0, sizeof(obuf));
    read(old_fd, obuf, 20);
    if (strcmp(obuf, "OLD_V1_CONTENT_DATA\n") != 0) {
        printf("FAIL: old_fd content contaminated: %s\n", obuf);
        close(old_fd); close(new_fd); return 1;
    }

    // 7. Close both cleanly
    if (close(old_fd) != 0) { perror("close old_fd"); return 1; }
    if (close(new_fd) != 0) { perror("close new_fd"); return 1; }

    run_cmd("/data/adb/ap/bin/nm rule del /system/etc/nmbench_smoke_5");
    printf("%s Test 5 PASS: Held FD retains original content across DEL/RE-ADD, clean close\n", LOG_PREFIX);
    return 0;
}

/* 6. Tmpfs 拦截与符号链接路径 */
static int test6_tmpfs_and_symlink(void) {
    printf("%s --- Test 6: Tmpfs Rejection & Symlink Bypass (§5.3.6) ---\n", LOG_PREFIX);
    char backing[256];
    snprintf(backing, sizeof(backing), "%s/backing6.txt", WORK_DIR);
    int b = open(backing, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    write(b, "SYMLINK_DATA_OK\n", 16);
    close(b);

    // Part A: Tmpfs rejection (TST-004)
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "/data/adb/ap/bin/nm rule add /dev/nmbench_smoke_tmpfs %s >/dev/null 2>&1", backing);
    int rc = run_cmd(cmd);
    if (rc == 0) {
        printf("FAIL: Rule on tmpfs /dev was NOT rejected!\n");
        return 1;
    }
    printf("%s Part A: Tmpfs rule rejected with rc=%d (TST-004 contract holds)\n", LOG_PREFIX, rc);

    // Part B: Symlink path through /vendor -> /system/vendor
    snprintf(cmd, sizeof(cmd), "/data/adb/ap/bin/nm rule add /system/vendor/etc/nmbench_smoke_symlink %s", backing);
    if (run_cmd(cmd) != 0) { printf("Failed to add symlink rule\n"); return 1; }

    // Access via /vendor/etc/nmbench_smoke_symlink
    int sfd = open("/vendor/etc/nmbench_smoke_symlink", O_RDONLY);
    if (sfd < 0) {
        printf("FAIL: Cannot open /vendor/etc/nmbench_smoke_symlink (symlink traverse failed)\n");
        run_cmd("/data/adb/ap/bin/nm rule del /system/vendor/etc/nmbench_smoke_symlink");
        return 1;
    }
    char sbuf[32] = {0};
    read(sfd, sbuf, 16);
    close(sfd);
    if (strcmp(sbuf, "SYMLINK_DATA_OK\n") != 0) {
        printf("FAIL: Symlink content mismatch: %s\n", sbuf);
        run_cmd("/data/adb/ap/bin/nm rule del /system/vendor/etc/nmbench_smoke_symlink");
        return 1;
    }

    run_cmd("/data/adb/ap/bin/nm rule del /system/vendor/etc/nmbench_smoke_symlink");
    printf("%s Test 6 PASS: Tmpfs rejection enforced, symlink resolution unharmed\n", LOG_PREFIX);
    return 0;
}

int main(int argc, char **argv) {
    printf("=== NoMount Minimum Smoke Test Suite (§5.3) ===\n");
    int initial_rules = get_rule_count();
    printf("Baseline rule count: %d\n", initial_rules);
    if (initial_rules != 47) {
        printf("ERROR: Initial rule count is %d, expected 47\n", initial_rules);
        return 1;
    }

    run_cmd("mkdir -p " WORK_DIR);

    int failures = 0;
    failures += test1_content_and_truncate();
    failures += test2_multi_fd_isolation();
    failures += test3_uid_policy();
    failures += test4_immediate_invisibility();
    failures += test5_readd_held_fd();
    failures += test6_tmpfs_and_symlink();

    run_cmd("rm -rf " WORK_DIR);

    int final_rules = get_rule_count();
    printf("Post-smoke rule count: %d\n", final_rules);
    if (final_rules != 47) {
        printf("ERROR: Post-smoke rule count is %d, expected 47!\n", final_rules);
        failures++;
    }

    if (failures == 0) {
        printf("=== ALL 6 SMOKE TESTS PASSED ===\n");
        return 0;
    } else {
        printf("=== %d SMOKE TEST(S) FAILED ===\n", failures);
        return 1;
    }
}

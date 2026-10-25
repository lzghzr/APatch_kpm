#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <sys/syscall.h>
#include <linux/stat.h>

#ifndef __NR_statx
#if defined(__aarch64__)
#define __NR_statx 291
#endif
#endif

#ifndef AT_STATX_SYNC_AS_STAT
#define AT_STATX_SYNC_AS_STAT 0x0000
#endif
#ifndef STATX_ALL
#define STATX_ALL 0x00000fffU
#endif

static int do_statx(int dirfd, const char *path, int flags, unsigned int mask, struct statx *stx) {
#ifdef __NR_statx
    return syscall(__NR_statx, dirfd, path, flags, mask, stx);
#else
    errno = ENOSYS;
    return -1;
#endif
}

typedef struct {
    double min;
    double p50;
    double p90;
    double p99;
    double max;
    double mean;
    double stddev;
    size_t count;
} PerfStats;

static int compare_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

static void calc_stats(double *samples, size_t n, PerfStats *out) {
    if (n == 0) {
        memset(out, 0, sizeof(*out));
        return;
    }
    qsort(samples, n, sizeof(double), compare_double);
    out->count = n;
    out->min = samples[0];
    out->max = samples[n - 1];
    out->p50 = samples[(size_t)(n * 0.50)];
    out->p90 = samples[(size_t)(n * 0.90)];
    out->p99 = samples[(size_t)(n * 0.99)];

    double sum = 0.0;
    for (size_t i = 0; i < n; i++) {
        sum += samples[i];
    }
    out->mean = sum / (double)n;

    double var_sum = 0.0;
    for (size_t i = 0; i < n; i++) {
        double diff = samples[i] - out->mean;
        var_sum += diff * diff;
    }
    out->stddev = sqrt(var_sum / (double)n);
}

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void drop_caches(void) {
    sync();
    int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (fd >= 0) {
        (void)write(fd, "3\n", 2);
        close(fd);
    }
}

/* ---------------- IDENTITY INSPECTION ---------------- */

typedef struct {
    char path[1024];
    bool is_dir;
    bool exists;

    // stat
    struct stat st;
    int st_rc;
    int st_err;

    // lstat
    struct stat lst;
    int lst_rc;
    int lst_err;

    // fstat
    struct stat fst;
    int fst_rc;
    int fst_err;

    // statx
    struct statx stx;
    int stx_rc;
    int stx_err;

    // statfs
    struct statfs sfs;
    int sfs_rc;
    int sfs_err;

    // fstatfs
    struct statfs fsfs;
    int fsfs_rc;
    int fsfs_err;

    // readlink
    char link_buf[1024];
    ssize_t link_rc;
    int link_err;

    // realpath
    char real_path[1024];
    bool realpath_ok;
    int realpath_err;

    // SELinux context
    char selinux_path[256];
    ssize_t selinux_path_rc;
    int selinux_path_err;

    char selinux_fd[256];
    ssize_t selinux_fd_rc;
    int selinux_fd_err;

    // access
    int r_ok;
    int w_ok;
    int x_ok;
} IdentityRecord;

static void inspect_identity(const char *path, IdentityRecord *rec) {
    memset(rec, 0, sizeof(*rec));
    snprintf(rec->path, sizeof(rec->path), "%s", path);

    // 1. stat
    rec->st_rc = stat(path, &rec->st);
    if (rec->st_rc != 0) rec->st_err = errno;
    rec->exists = (rec->st_rc == 0);
    rec->is_dir = rec->exists && S_ISDIR(rec->st.st_mode);

    // 2. lstat
    rec->lst_rc = lstat(path, &rec->lst);
    if (rec->lst_rc != 0) rec->lst_err = errno;

    // 3. statx
    memset(&rec->stx, 0, sizeof(rec->stx));
    rec->stx_rc = do_statx(AT_FDCWD, path, AT_STATX_SYNC_AS_STAT, STATX_ALL, &rec->stx);
    if (rec->stx_rc != 0) rec->stx_err = errno;

    // 4. open + fstat + fstatfs + fgetxattr
    int flags = O_RDONLY;
    if (rec->is_dir) flags |= O_DIRECTORY;
    int fd = open(path, flags);
    if (fd >= 0) {
        rec->fst_rc = fstat(fd, &rec->fst);
        if (rec->fst_rc != 0) rec->fst_err = errno;

        rec->fsfs_rc = fstatfs(fd, &rec->fsfs);
        if (rec->fsfs_rc != 0) rec->fsfs_err = errno;

        rec->selinux_fd_rc = fgetxattr(fd, "security.selinux", rec->selinux_fd, sizeof(rec->selinux_fd) - 1);
        if (rec->selinux_fd_rc >= 0) {
            rec->selinux_fd[rec->selinux_fd_rc] = '\0';
        } else {
            rec->selinux_fd_err = errno;
        }
        close(fd);
    } else {
        rec->fst_rc = -1;
        rec->fst_err = errno;
        rec->fsfs_rc = -1;
        rec->fsfs_err = errno;
        rec->selinux_fd_rc = -1;
        rec->selinux_fd_err = errno;
    }

    // 5. statfs
    rec->sfs_rc = statfs(path, &rec->sfs);
    if (rec->sfs_rc != 0) rec->sfs_err = errno;

    // 6. readlink
    rec->link_rc = readlink(path, rec->link_buf, sizeof(rec->link_buf) - 1);
    if (rec->link_rc >= 0) {
        rec->link_buf[rec->link_rc] = '\0';
    } else {
        rec->link_err = errno;
    }

    // 7. realpath
    if (realpath(path, rec->real_path) != NULL) {
        rec->realpath_ok = true;
    } else {
        rec->realpath_ok = false;
        rec->realpath_err = errno;
    }

    // 8. lgetxattr (SELinux)
    rec->selinux_path_rc = lgetxattr(path, "security.selinux", rec->selinux_path, sizeof(rec->selinux_path) - 1);
    if (rec->selinux_path_rc >= 0) {
        rec->selinux_path[rec->selinux_path_rc] = '\0';
    } else {
        rec->selinux_path_err = errno;
    }

    // 9. access
    rec->r_ok = access(path, R_OK);
    rec->w_ok = access(path, W_OK);
    rec->x_ok = access(path, X_OK);
}

static const char *fs_type_str(long type) {
    switch (type) {
        case 0xef53: return "EXT4";
        case 0xf2f52010: return "F2FS";
        case 0x58465342: return "XFS";
        case 0x73636673: return "SDCARDFS";
        case 0x69656566: return "EROFS";
        case 0x9fa0: return "ANON_INODE_FS";
        default: return "OTHER";
    }
}

static void print_identity_diff(const IdentityRecord *m, const IdentityRecord *s, const char *title) {
    printf("### 对比组：%s\n\n", title);
    printf("- **受管理路径 (Managed)**: `%s`\n", m->path);
    printf("- **直访源路径 (Source)**: `%s`\n\n", s->path);

    printf("| 系统调用 / 属性分类 | 字段名 | 受管理路径 (Managed) | 直访源路径 (Source) | 一致性 | 差异备注 |\n");
    printf("| --- | --- | --- | --- | :---: | --- |\n");

    // stat fields
    #define CMP_STAT_FMT(field, fmt, cast, note) do { \
        bool match = (m->st.field == s->st.field); \
        printf("| `stat()` | `%s` | " fmt " | " fmt " | %s | %s |\n", \
               #field, (cast)m->st.field, (cast)s->st.field, match ? "MATCH" : "**DIFF**", match ? "-" : note); \
    } while(0)

    CMP_STAT_FMT(st_dev, "0x%llx", unsigned long long, "设备号：受管理路径反映挂载点所在设备");
    CMP_STAT_FMT(st_ino, "%llu", unsigned long long, "Inode 号：受管理路径由 NoMount 虚拟生成");
    CMP_STAT_FMT(st_mode, "0%o", unsigned int, "文件模式与权限位");
    CMP_STAT_FMT(st_nlink, "%llu", unsigned long long, "硬链接数");
    CMP_STAT_FMT(st_uid, "%u", unsigned int, "所有者 UID");
    CMP_STAT_FMT(st_gid, "%u", unsigned int, "所属组 GID");
    CMP_STAT_FMT(st_rdev, "0x%llx", unsigned long long, "特殊设备号");
    CMP_STAT_FMT(st_size, "%lld B", long long, "文件尺寸（字节）");
    CMP_STAT_FMT(st_blksize, "%ld B", long, "I/O 块大小");
    CMP_STAT_FMT(st_blocks, "%lld", long long, "512B 扇区块数");

    printf("| `stat()` | `st_atim` | %ld.%09ld | %ld.%09ld | %s | %s |\n",
           (long)m->st.st_atime, (long)m->st.st_atim.tv_nsec,
           (long)s->st.st_atime, (long)s->st.st_atim.tv_nsec,
           (m->st.st_atime == s->st.st_atime && m->st.st_atim.tv_nsec == s->st.st_atim.tv_nsec) ? "MATCH" : "**DIFF**",
           (m->st.st_atime == s->st.st_atime && m->st.st_atim.tv_nsec == s->st.st_atim.tv_nsec) ? "-" : "访问时间戳");

    printf("| `stat()` | `st_mtim` | %ld.%09ld | %ld.%09ld | %s | %s |\n",
           (long)m->st.st_mtime, (long)m->st.st_mtim.tv_nsec,
           (long)s->st.st_mtime, (long)s->st.st_mtim.tv_nsec,
           (m->st.st_mtime == s->st.st_mtime && m->st.st_mtim.tv_nsec == s->st.st_mtim.tv_nsec) ? "MATCH" : "**DIFF**",
           (m->st.st_mtime == s->st.st_mtime && m->st.st_mtim.tv_nsec == s->st.st_mtim.tv_nsec) ? "-" : "修改时间戳");

    printf("| `stat()` | `st_ctim` | %ld.%09ld | %ld.%09ld | %s | %s |\n",
           (long)m->st.st_ctime, (long)m->st.st_ctim.tv_nsec,
           (long)s->st.st_ctime, (long)s->st.st_ctim.tv_nsec,
           (m->st.st_ctime == s->st.st_ctime && m->st.st_ctim.tv_nsec == s->st.st_ctim.tv_nsec) ? "MATCH" : "**DIFF**",
           (m->st.st_ctime == s->st.st_ctime && m->st.st_ctim.tv_nsec == s->st.st_ctim.tv_nsec) ? "-" : "元数据修改时间戳");

    #undef CMP_STAT_FMT

    // fstat fields
    printf("| `fstat()` | `st_dev` | 0x%llx (%llu) | 0x%llx (%llu) | %s | %s |\n",
           (unsigned long long)m->fst.st_dev, (unsigned long long)m->fst.st_dev,
           (unsigned long long)s->fst.st_dev, (unsigned long long)s->fst.st_dev,
           (m->fst.st_dev == s->fst.st_dev) ? "MATCH" : "**DIFF**",
           (m->fst.st_dev == s->fst.st_dev) ? "-" : "文件句柄设备号");

    printf("| `fstat()` | `st_ino` | %llu | %llu | %s | %s |\n",
           (unsigned long long)m->fst.st_ino, (unsigned long long)s->fst.st_ino,
           (m->fst.st_ino == s->fst.st_ino) ? "MATCH" : "**DIFF**",
           (m->fst.st_ino == s->fst.st_ino) ? "-" : "文件句柄 Inode 号");

    printf("| `fstat()` | `st_size` | %lld B | %lld B | %s | %s |\n",
           (long long)m->fst.st_size, (long long)s->fst.st_size,
           (m->fst.st_size == s->fst.st_size) ? "MATCH" : "**DIFF**", "-");

    printf("| `fstat()` | `st_mode` | 0%o | 0%o | %s | %s |\n",
           (unsigned int)m->fst.st_mode, (unsigned int)s->fst.st_mode,
           (m->fst.st_mode == s->fst.st_mode) ? "MATCH" : "**DIFF**", "-");

    // statx fields
    if (m->stx_rc == 0 && s->stx_rc == 0) {
        printf("| `statx()` | `stx_dev` | %u:%u | %u:%u | %s | %s |\n",
               m->stx.stx_dev_major, m->stx.stx_dev_minor,
               s->stx.stx_dev_major, s->stx.stx_dev_minor,
               (m->stx.stx_dev_major == s->stx.stx_dev_major && m->stx.stx_dev_minor == s->stx.stx_dev_minor) ? "MATCH" : "**DIFF**",
               (m->stx.stx_dev_major == s->stx.stx_dev_major && m->stx.stx_dev_minor == s->stx.stx_dev_minor) ? "-" : "主次设备号");

        printf("| `statx()` | `stx_ino` | %llu | %llu | %s | %s |\n",
               (unsigned long long)m->stx.stx_ino, (unsigned long long)s->stx.stx_ino,
               (m->stx.stx_ino == s->stx.stx_ino) ? "MATCH" : "**DIFF**",
               (m->stx.stx_ino == s->stx.stx_ino) ? "-" : "statx 扩展 Inode");

        printf("| `statx()` | `stx_mode` | 0%o | 0%o | %s | %s |\n",
               (unsigned int)m->stx.stx_mode, (unsigned int)s->stx.stx_mode,
               (m->stx.stx_mode == s->stx.stx_mode) ? "MATCH" : "**DIFF**", "-");

        printf("| `statx()` | `stx_size` | %llu B | %llu B | %s | %s |\n",
               (unsigned long long)m->stx.stx_size, (unsigned long long)s->stx.stx_size,
               (m->stx.stx_size == s->stx.stx_size) ? "MATCH" : "**DIFF**", "-");

        printf("| `statx()` | `stx_blocks` | %llu | %llu | %s | %s |\n",
               (unsigned long long)m->stx.stx_blocks, (unsigned long long)s->stx.stx_blocks,
               (m->stx.stx_blocks == s->stx.stx_blocks) ? "MATCH" : "**DIFF**", "-");

        printf("| `statx()` | `stx_attributes` | 0x%llx | 0x%llx | %s | %s |\n",
               (unsigned long long)m->stx.stx_attributes, (unsigned long long)s->stx.stx_attributes,
               (m->stx.stx_attributes == s->stx.stx_attributes) ? "MATCH" : "**DIFF**", "-");
    } else {
        printf("| `statx()` | `status` | rc=%d err=%d | rc=%d err=%d | %s | statx 系统调用支持情况 |\n",
               m->stx_rc, m->stx_err, s->stx_rc, s->stx_err,
               (m->stx_rc == s->stx_rc) ? "MATCH" : "**DIFF**");
    }

    // statfs fields
    printf("| `statfs()` | `f_type` | 0x%lx (%s) | 0x%lx (%s) | %s | %s |\n",
           (unsigned long)m->sfs.f_type, fs_type_str(m->sfs.f_type),
           (unsigned long)s->sfs.f_type, fs_type_str(s->sfs.f_type),
           (m->sfs.f_type == s->sfs.f_type) ? "MATCH" : "**DIFF**",
           (m->sfs.f_type == s->sfs.f_type) ? "-" : "文件系统类型魔数");

    printf("| `statfs()` | `f_bsize` | %ld B | %ld B | %s | %s |\n",
           (long)m->sfs.f_bsize, (long)s->sfs.f_bsize,
           (m->sfs.f_bsize == s->sfs.f_bsize) ? "MATCH" : "**DIFF**", "-");

    printf("| `statfs()` | `f_blocks` | %llu | %llu | %s | %s |\n",
           (unsigned long long)m->sfs.f_blocks, (unsigned long long)s->sfs.f_blocks,
           (m->sfs.f_blocks == s->sfs.f_blocks) ? "MATCH" : "**DIFF**",
           (m->sfs.f_blocks == s->sfs.f_blocks) ? "-" : "总块数（反映所在文件系统）");

    printf("| `statfs()` | `f_bfree` | %llu | %llu | %s | %s |\n",
           (unsigned long long)m->sfs.f_bfree, (unsigned long long)s->sfs.f_bfree,
           (m->sfs.f_bfree == s->sfs.f_bfree) ? "MATCH" : "**DIFF**",
           (m->sfs.f_bfree == s->sfs.f_bfree) ? "-" : "剩余块数");

    printf("| `statfs()` | `f_files` | %llu | %llu | %s | %s |\n",
           (unsigned long long)m->sfs.f_files, (unsigned long long)s->sfs.f_files,
           (m->sfs.f_files == s->sfs.f_files) ? "MATCH" : "**DIFF**",
           (m->sfs.f_files == s->sfs.f_files) ? "-" : "Inode 总容量");

    printf("| `statfs()` | `f_namelen` | %ld | %ld | %s | %s |\n",
           (long)m->sfs.f_namelen, (long)s->sfs.f_namelen,
           (m->sfs.f_namelen == s->sfs.f_namelen) ? "MATCH" : "**DIFF**", "-");

    // fstatfs fields
    printf("| `fstatfs()` | `f_type` | 0x%lx (%s) | 0x%lx (%s) | %s | %s |\n",
           (unsigned long)m->fsfs.f_type, fs_type_str(m->fsfs.f_type),
           (unsigned long)s->fsfs.f_type, fs_type_str(s->fsfs.f_type),
           (m->fsfs.f_type == s->fsfs.f_type) ? "MATCH" : "**DIFF**",
           (m->fsfs.f_type == s->fsfs.f_type) ? "-" : "打开句柄的文件系统魔数");

    // readlink / realpath
    printf("| `readlink()` | `target` | %s | %s | %s | %s |\n",
           (m->link_rc >= 0) ? m->link_buf : "(errno/non-symlink)",
           (s->link_rc >= 0) ? s->link_buf : "(errno/non-symlink)",
           (m->link_rc == s->link_rc && (m->link_rc < 0 || strcmp(m->link_buf, s->link_buf) == 0)) ? "MATCH" : "**DIFF**",
           "符号链接读取行为");

    printf("| `realpath()` | `path` | `%s` | `%s` | %s | %s |\n",
           m->realpath_ok ? m->real_path : "(error)",
           s->realpath_ok ? s->real_path : "(error)",
           (m->realpath_ok && s->realpath_ok && strcmp(m->real_path, s->real_path) == 0) ? "MATCH" : "**DIFF**",
           "绝对规范化路径（受管理路径返回自身虚拟位置）");

    // SELinux
    printf("| `getxattr()` | `security.selinux` | `%s` | `%s` | %s | %s |\n",
           (m->selinux_path_rc >= 0) ? m->selinux_path : "(none/error)",
           (s->selinux_path_rc >= 0) ? s->selinux_path : "(none/error)",
           (m->selinux_path_rc >= 0 && s->selinux_path_rc >= 0 && strcmp(m->selinux_path, s->selinux_path) == 0) ? "MATCH" : "**DIFF**",
           "文件路径 SELinux 标签");

    printf("| `fgetxattr()` | `security.selinux` | `%s` | `%s` | %s | %s |\n",
           (m->selinux_fd_rc >= 0) ? m->selinux_fd : "(none/error)",
           (s->selinux_fd_rc >= 0) ? s->selinux_fd : "(none/error)",
           (m->selinux_fd_rc >= 0 && s->selinux_fd_rc >= 0 && strcmp(m->selinux_fd, s->selinux_fd) == 0) ? "MATCH" : "**DIFF**",
           "打开句柄 SELinux 标签");

    // DAC access
    printf("| `access()` | `R_OK/W_OK/X_OK` | R=%d W=%d X=%d | R=%d W=%d X=%d | %s | %s |\n",
           m->r_ok, m->w_ok, m->x_ok,
           s->r_ok, s->w_ok, s->x_ok,
           (m->r_ok == s->r_ok && m->w_ok == s->w_ok && m->x_ok == s->x_ok) ? "MATCH" : "**DIFF**",
           "DAC 访问检查结果（0 为允许，-1 为拒绝）");

    printf("\n");
}

/* ---------------- PERFORMANCE BENCHMARK ---------------- */

typedef struct {
    PerfStats open_close;
    PerfStats stat_op;
    PerfStats fstat_op;
    PerfStats statx_op;
    PerfStats read_op;
    PerfStats readdir_op;
} PathPerfResult;

static void run_perf_benchmark(const char *path, bool is_dir, size_t n_iters, bool cold, PathPerfResult *res) {
    memset(res, 0, sizeof(*res));
    double *buf_times = (double *)malloc(n_iters * sizeof(double));
    if (!buf_times) {
        fprintf(stderr, "malloc failed\n");
        return;
    }

    char read_buf[4096];
    struct stat st;
    struct statx stx;

    // 1. open + close
    for (size_t i = 0; i < n_iters; i++) {
        if (cold) drop_caches();
        uint64_t t1 = get_time_ns();
        int fd = open(path, is_dir ? (O_RDONLY | O_DIRECTORY) : O_RDONLY);
        if (fd >= 0) close(fd);
        uint64_t t2 = get_time_ns();
        buf_times[i] = (double)(t2 - t1) / 1000.0; // us
    }
    calc_stats(buf_times, n_iters, &res->open_close);

    // 2. stat
    for (size_t i = 0; i < n_iters; i++) {
        if (cold) drop_caches();
        uint64_t t1 = get_time_ns();
        (void)stat(path, &st);
        uint64_t t2 = get_time_ns();
        buf_times[i] = (double)(t2 - t1) / 1000.0; // us
    }
    calc_stats(buf_times, n_iters, &res->stat_op);

    // 3. fstat
    int fd_test = open(path, is_dir ? (O_RDONLY | O_DIRECTORY) : O_RDONLY);
    if (fd_test >= 0) {
        for (size_t i = 0; i < n_iters; i++) {
            if (cold) drop_caches();
            uint64_t t1 = get_time_ns();
            (void)fstat(fd_test, &st);
            uint64_t t2 = get_time_ns();
            buf_times[i] = (double)(t2 - t1) / 1000.0; // us
        }
        close(fd_test);
    }
    calc_stats(buf_times, n_iters, &res->fstat_op);

    // 4. statx
    for (size_t i = 0; i < n_iters; i++) {
        if (cold) drop_caches();
        uint64_t t1 = get_time_ns();
        (void)do_statx(AT_FDCWD, path, AT_STATX_SYNC_AS_STAT, STATX_ALL, &stx);
        uint64_t t2 = get_time_ns();
        buf_times[i] = (double)(t2 - t1) / 1000.0; // us
    }
    calc_stats(buf_times, n_iters, &res->statx_op);

    // 5. read (for regular files)
    if (!is_dir) {
        int rfd = open(path, O_RDONLY);
        if (rfd >= 0) {
            for (size_t i = 0; i < n_iters; i++) {
                if (cold) drop_caches();
                uint64_t t1 = get_time_ns();
                (void)pread(rfd, read_buf, sizeof(read_buf), 0);
                uint64_t t2 = get_time_ns();
                buf_times[i] = (double)(t2 - t1) / 1000.0; // us
            }
            close(rfd);
        }
        calc_stats(buf_times, n_iters, &res->read_op);
    }

    // 6. readdir (for directory)
    if (is_dir) {
        for (size_t i = 0; i < n_iters; i++) {
            if (cold) drop_caches();
            uint64_t t1 = get_time_ns();
            DIR *d = opendir(path);
            if (d) {
                struct dirent *de;
                while ((de = readdir(d)) != NULL) {
                    (void)de->d_name;
                }
                closedir(d);
            }
            uint64_t t2 = get_time_ns();
            buf_times[i] = (double)(t2 - t1) / 1000.0; // us
        }
        calc_stats(buf_times, n_iters, &res->readdir_op);
    }

    free(buf_times);
}

static void print_perf_table_row(const char *op_name, const char *path_tag, const PerfStats *st) {
    printf("| %s | %s | %zu | %.2f µs | %.2f µs | %.2f µs | %.2f µs | %.2f µs | %.2f ± %.2f µs |\n",
           op_name, path_tag, st->count, st->min, st->p50, st->p90, st->p99, st->max, st->mean, st->stddev);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s --identity <managed_path> <source_path> <group_title>\n", argv[0]);
        fprintf(stderr, "  %s --perf <managed_path> <unmanaged_path> <is_dir:0|1> <iterations> <cold:0|1>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--identity") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Need managed_path, source_path, group_title\n");
            return 1;
        }
        IdentityRecord m_rec, s_rec;
        inspect_identity(argv[2], &m_rec);
        inspect_identity(argv[3], &s_rec);
        print_identity_diff(&m_rec, &s_rec, argv[4]);
        return 0;
    }

    if (strcmp(argv[1], "--perf") == 0) {
        if (argc < 7) {
            fprintf(stderr, "Need managed_path, unmanaged_path, is_dir, iters, cold\n");
            return 1;
        }
        const char *m_path = argv[2];
        const char *u_path = argv[3];
        bool is_dir = (atoi(argv[4]) != 0);
        size_t iters = (size_t)atoi(argv[5]);
        bool cold = (atoi(argv[6]) != 0);

        printf("#### 性能对比（%s 缓存，重复 %zu 次）\n\n", cold ? "冷" : "热", iters);
        printf("- **受管理路径 (Managed)**: `%s`\n", m_path);
        printf("- **对照路径 (Unmanaged)**: `%s`\n\n", u_path);
        printf("| 操作 | 路径类型 | 采样数 | Min | P50 (中位数) | P90 | P99 | Max | 均值 ± 标准差 |\n");
        printf("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");

        PathPerfResult m_res, u_res;
        run_perf_benchmark(m_path, is_dir, iters, cold, &m_res);
        run_perf_benchmark(u_path, is_dir, iters, cold, &u_res);

        print_perf_table_row("open + close", "受管理 (Managed)", &m_res.open_close);
        print_perf_table_row("open + close", "对照组 (Unmanaged)", &u_res.open_close);

        print_perf_table_row("stat", "受管理 (Managed)", &m_res.stat_op);
        print_perf_table_row("stat", "对照组 (Unmanaged)", &u_res.stat_op);

        print_perf_table_row("fstat", "受管理 (Managed)", &m_res.fstat_op);
        print_perf_table_row("fstat", "对照组 (Unmanaged)", &u_res.fstat_op);

        print_perf_table_row("statx", "受管理 (Managed)", &m_res.statx_op);
        print_perf_table_row("statx", "对照组 (Unmanaged)", &u_res.statx_op);

        if (!is_dir) {
            print_perf_table_row("read (4KB pread)", "受管理 (Managed)", &m_res.read_op);
            print_perf_table_row("read (4KB pread)", "对照组 (Unmanaged)", &u_res.read_op);
        } else {
            print_perf_table_row("readdir (遍历)", "受管理 (Managed)", &m_res.readdir_op);
            print_perf_table_row("readdir (遍历)", "对照组 (Unmanaged)", &u_res.readdir_op);
        }
        printf("\n");
        return 0;
    }

    fprintf(stderr, "Unknown mode: %s\n", argv[1]);
    return 1;
}

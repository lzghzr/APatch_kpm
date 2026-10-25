#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static void wait_for_trigger(const char *expected) {
    char buf[64];
    while (1) {
        FILE *f = fopen("/data/local/tmp/held_step", "r");
        if (f) {
            if (fgets(buf, sizeof(buf), f)) {
                buf[strcspn(buf, "\r\n")] = 0;
                if (strcmp(buf, expected) == 0) {
                    fclose(f);
                    return;
                }
            }
            fclose(f);
        }
        usleep(50000); // 50ms
    }
}

int main(int argc, char **argv) {
    const char *target = (argc > 1) ? argv[1] : "/system/etc/vdac";
    printf("[held-FD] starting under uid=%d, euid=%d, gid=%d, egid=%d\n",
           getuid(), geteuid(), getgid(), getegid());
    fflush(stdout);

    // 1. Open directory fd
    int fd = open(target, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        printf("[held-FD] open(\"%s\") failed: errno=%d (%s)\n", target, errno, strerror(errno));
        return 1;
    }
    printf("[held-FD] successfully opened \"%s\", fd=%d\n", target, fd);
    fflush(stdout);

    // 2. Initial fchdir(fd)
    int rc = fchdir(fd);
    int err = errno;
    printf("[held-FD] Phase 1 (baseline): fchdir(fd=%d) -> rc=%d, errno=%d (%s)\n",
           fd, rc, rc < 0 ? err : 0, rc < 0 ? strerror(err) : "Success");
    fflush(stdout);

    // Write handshake: "phase1_done"
    FILE *f = fopen("/data/local/tmp/held_status", "w");
    if (f) { fprintf(f, "phase1_done\n"); fclose(f); }

    // 3. Wait for trigger to test tightened permissions
    wait_for_trigger("tighten");

    // Phase 2: fchdir(fd) with tightened source
    rc = fchdir(fd);
    err = errno;
    printf("[held-FD] Phase 2 (tightened): fchdir(fd=%d) -> rc=%d, errno=%d (%s)\n",
           fd, rc, rc < 0 ? err : 0, rc < 0 ? strerror(err) : "Success");
    fflush(stdout);

    f = fopen("/data/local/tmp/held_status", "w");
    if (f) { fprintf(f, "phase2_done\n"); fclose(f); }

    // 4. Wait for trigger to test restored permissions
    wait_for_trigger("restore");

    // Phase 3: fchdir(fd) with restored permissions
    rc = fchdir(fd);
    err = errno;
    printf("[held-FD] Phase 3 (restored): fchdir(fd=%d) -> rc=%d, errno=%d (%s)\n",
           fd, rc, rc < 0 ? err : 0, rc < 0 ? strerror(err) : "Success");
    fflush(stdout);

    close(fd);
    printf("[held-FD] closed fd=%d, test finished.\n", fd);
    return 0;
}

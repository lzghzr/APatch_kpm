#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#define PAGE_SIZE 4096

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    uint8_t buf[PAGE_SIZE];
    uint8_t zero_buf[PAGE_SIZE];
    memset(zero_buf, 0, PAGE_SIZE);

    size_t total_pages = 0;
    size_t zero_pages = 0;
    size_t nonzero_pages = 0;
    ssize_t n;

    while ((n = read(fd, buf, PAGE_SIZE)) == PAGE_SIZE) {
        total_pages++;
        if (memcmp(buf, zero_buf, PAGE_SIZE) == 0) {
            zero_pages++;
        } else {
            nonzero_pages++;
        }
    }
    close(fd);

    printf("File: %s\n", path);
    printf("Total pages:   %zu (%zu bytes)\n", total_pages, total_pages * PAGE_SIZE);
    printf("Zero pages:    %zu (%.4f%%)\n", zero_pages, total_pages ? (zero_pages * 100.0 / total_pages) : 0.0);
    printf("Non-zero pages:%zu (%.4f%%)\n", nonzero_pages, total_pages ? (nonzero_pages * 100.0 / total_pages) : 0.0);

    return 0;
}

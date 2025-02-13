#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define PAGE_SIZE  (1UL << 12)
#define MMAP_SIZE  (16UL << 20)

uint64_t get_timestamp(void)
{
    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC, &tp);

    return tp.tv_sec * 1000000000UL + tp.tv_nsec;
}

int main(int argc, char *argv[])
{
    char *p, *c;
    uint64_t t0, t1;

    p = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    for (c = p; c < p + MMAP_SIZE; c += PAGE_SIZE) {
        *c = 'A';
    }
    
    if (argc == 2 && !strcmp(argv[1], "--linux-fork")) {
        int pid;
        if ((pid = fork())) {
            waitpid(pid, NULL, 0);
            exit(0);
        }
    } else if (argc == 2 && !strcmp(argv[1], "--sc-snapshot")) {
        syscall(0x1000);
    }

    t0 = get_timestamp();
    for (c = p; c < p + MMAP_SIZE; c += PAGE_SIZE) {
        *c = 'B';
    }
    t1 = get_timestamp();
    printf("latency %f\n", (double)(t1 - t0) / (MMAP_SIZE / PAGE_SIZE));

    return 0;
}

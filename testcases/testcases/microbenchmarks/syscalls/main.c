#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <pthread.h>

#define PAGE_SIZE  (1UL << 12)
#define MMAP_SIZE  (16UL << 20)
#define BLOCK_SIZE   (512)

typedef void (*fn_t)(void *);

uint64_t get_timestamp(void)
{
    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC, &tp);

    return tp.tv_sec * 1000000000UL + tp.tv_nsec;
}

uint64_t repeat(int n, fn_t fn, void *arg)
{
    int i;
    unsigned long t0, t1;

    t0 = get_timestamp();

    for (i = 0; i < n; i++) {
        fn(arg);
    }

    t1 = get_timestamp();

    return (t1 - t0) / n;
}

void do_getpid(void *arg)
{
    getpid();
}

void do_mmap_munmap(void *arg)
{
    void *p;

    p = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(p, MMAP_SIZE);
}

void do_pgfault(void *arg)
{
    char *p, *c;

    p = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    for (c = p; c < p + MMAP_SIZE; c += PAGE_SIZE) {
        *c = 'A';
    }

    munmap(p, MMAP_SIZE);
}

void do_lseek(void *arg)
{
    int fd = (long)arg;

    lseek(fd, 0, SEEK_SET);
}

void do_write(void *arg)
{
    int fd = (long)arg;
    char buf[BLOCK_SIZE];

    lseek(fd, 0, SEEK_SET);
    write(fd, buf, BLOCK_SIZE);
}

void do_read(void *arg)
{
    int fd = (long)arg;
    char buf[BLOCK_SIZE];

    pread(fd, buf, BLOCK_SIZE, 0);
}

void do_open_close(void *arg)
{
    int fd;

    fd = open(arg, O_RDONLY);
    close(fd);
}

void do_mprotect(void *arg)
{
    mprotect(arg, PAGE_SIZE, PROT_READ);
    mprotect(arg, PAGE_SIZE, PROT_READ | PROT_WRITE);
}

void *pipe_server(void *arg)
{
    int *pipefd = arg;
    char c;

    for (;;) {
        read(pipefd[0], &c, 1);
        if (c == 'X') {
            return NULL;
        }
        write(pipefd[1], &c, 1);
    }
}

void do_pipe(void *arg)
{
    int *pipefd = arg;
    char c = 'A';

    write(pipefd[1], &c, 1);
    read(pipefd[0], &c, 1);
}

void *eventfd_server(void *arg)
{
    int *efd = arg;
    unsigned int val;

    for (;;) {
        read(efd[0], &val, sizeof(val));
        if (val == 123) {
            return NULL;
        }
        val = 1;
        write(efd[1], &val, sizeof(val));
    }
}

void do_eventfd(void *arg)
{
    int *efd = arg;
    unsigned int val;

    val = 1;
    write(efd[0], &val, sizeof(val));
    read(efd[1], &val, sizeof(val));
}

int main(void)
{
    int fd;
    void *p;
    int pipefd[2];
    int efd[2];
    pthread_t pthread;

    uint64_t t_getpid;
    uint64_t t_mmap_munmap;
    uint64_t t_pgfault;
    uint64_t t_mprotect;
    uint64_t t_tmpfs_lseek;
    uint64_t t_tmpfs_write;
    uint64_t t_rootfs_read;
    uint64_t t_rootfs_open_close;
    uint64_t t_pipe;
    uint64_t t_eventfd;

    /* getpid */
    t_getpid = repeat(100, do_getpid, NULL);

    /* mmap/munmap */
    t_mmap_munmap = repeat(1000, do_mmap_munmap, NULL);

    /* pgfault */
    t_pgfault = repeat(1000, do_pgfault, NULL);
    t_pgfault = (t_pgfault - t_mmap_munmap) / (MMAP_SIZE / PAGE_SIZE);

    /* mprotect */
    p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    *(char *)p = 'A';
    t_mprotect = repeat(1000, do_mprotect, p);
    munmap(p, PAGE_SIZE);
    t_mprotect /= 2;

    /* write (tmpfs) */
    fd = open("/tmp/xxx", O_RDWR);
    t_tmpfs_lseek = repeat(100, do_lseek, (void *)(long)fd);
    t_tmpfs_write = repeat(100, do_write, (void *)(long)fd);
    t_tmpfs_write -= t_tmpfs_lseek;
    close(fd);

    /* read (rootfs) */
    fd = open("/func/main.c", O_RDONLY);
    t_rootfs_read = repeat(100, do_read, (void *)(long)fd);
    close(fd);

    /* open/close (rootfs) */
    t_rootfs_open_close = repeat(100, do_open_close, "/func/main.c");

    /* pipe */
    pipe(pipefd);
    pthread_create(&pthread, NULL, pipe_server, pipefd);
    t_pipe = repeat(100, do_pipe, pipefd);
    t_pipe /= 2;
    write(pipefd[1], "X", 1);
    pthread_join(pthread, NULL);

    /* eventfd */
    efd[0] = eventfd(0, 0);
    efd[1] = eventfd(0, 0);
    pthread_create(&pthread, NULL, eventfd_server, efd);
    t_eventfd = repeat(100, do_eventfd, efd);
    t_eventfd /= 2;

    printf("{");
    printf("\"t_getpid\": %lu, ", t_getpid);
    printf("\"t_mmap_munmap\": %lu, ", t_mmap_munmap);
    printf("\"t_pgfault\": %lu, ", t_pgfault);
    printf("\"t_mprotect\": %lu, ", t_mprotect);
    printf("\"t_tmpfs_write\": %lu, ", t_tmpfs_write);
    printf("\"t_rootfs_read\": %lu, ", t_rootfs_read);
    printf("\"t_rootfs_open_close\": %lu, ", t_rootfs_open_close);
    printf("\"t_pipe\": %lu, ", t_pipe);
    printf("\"t_eventfd\": %lu", t_eventfd);
    printf("}\n");

    return 0;
}

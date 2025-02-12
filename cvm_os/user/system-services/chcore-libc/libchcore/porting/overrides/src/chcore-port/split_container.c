#ifdef CHCORE_SPLIT_CONTAINER
#define _GNU_SOURCE
#include "syscall.h"
#include "chcore_mman.h"
#include <chcore/bug.h>
#include <chcore/memory.h>
#include <chcore/syscall.h>
#include <chcore/pmu.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <futex.h>
#include <sched.h>
#include <termios.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/times.h>
#include <chcore-internal/fs_defs.h>
#include <netinet/in.h>
#include "split_container.h"
#include "fd.h"
#include "raw_syscall.h"
#include "pthread_impl.h"
#include <chcore/sc_shm.h>
#include "file.h"
#include "poll.h"
#include "flo-shani.h"
#include "flo-aesni.h"
#include "libtmpfs.h"

#define EDONTHOOK 255

#define AES128_Rounds   11
#define BLKSIZE         512
#define HDRSIZE         1024
#undef ALIGN
#define ALIGN(n) __attribute__((aligned(n)))
static u8 iv[AES_BlockSize / 8] ALIGN(64);
static u8 round_keys[(AES_BlockSize / 8) * (AES128_Rounds + 1)] ALIGN(64);

#define SC_FILE_TYPE_TMP          1
#define SC_FILE_TYPE_LIB          2
#define SC_FILE_TYPE_NET          3
#define SC_FILE_TYPE_STDIO        4
#define SC_FILE_TYPE_EPOLL        5
#define SC_FILE_TYPE_NET_NOENC    6

static int is_enclave = 0;
static int use_cache = 0;
#ifdef CHCORE_SPLIT_CONTAINER_LIBTMPFS
static int use_libtmpfs = 1;
#else /* CHCORE_SPLIT_CONTAINER_LIBTMPFS */
static int use_libtmpfs = 0;
#endif /* CHCORE_SPLIT_CONTAINER_LIBTMPFS */
static int use_polling = 0;
static int use_defer_encrypt = 0;
#ifndef CHCORE_SPLIT_CONTAINER_SYNC
static int use_sync = 0;
#endif /* CHCORE_SPLIT_CONTAINER_SYNC */

static int dsys_cnt_lib = 0;
static int dsys_cnt_tmp = 0;
static int dsys_cnt_net = 0;
static int dsys_cnt_all = 0;
static int io_cnt_lib = 0;
static int io_cnt_tmp = 0;
static int io_cnt_net = 0;
static unsigned long t_delegate = 0;
static unsigned long t_attest = 0;
static unsigned long t_encrypt = 0;
static unsigned long t_redirect = 0;
static volatile unsigned long t_pgfault = 0;

static unsigned long defer_encrypt_cnt = 0;

static unsigned long base_real_time_ns;
static unsigned long base_mono_time_ns;

#define fd_dsys_stat(fd) do { \
        if (fd_dic[fd]->sc_file_type == SC_FILE_TYPE_LIB) \
                a_fetch_add(&dsys_cnt_lib, 1); \
        else if (fd_dic[fd]->sc_file_type == SC_FILE_TYPE_TMP && !use_libtmpfs) \
                a_fetch_add(&dsys_cnt_tmp, 1); \
        else if (fd_dic[fd]->sc_file_type == SC_FILE_TYPE_NET || \
                 fd_dic[fd]->sc_file_type == SC_FILE_TYPE_NET_NOENC) \
                a_fetch_add(&dsys_cnt_net, 1); \
} while (0)

#define fd_io_stat(fd, io) do { \
        if (fd_dic[fd]->sc_file_type == SC_FILE_TYPE_LIB) \
                a_fetch_add(&io_cnt_lib, io); \
        else if (fd_dic[fd]->sc_file_type == SC_FILE_TYPE_TMP && !use_libtmpfs) \
                a_fetch_add(&io_cnt_tmp, io); \
        else if (fd_dic[fd]->sc_file_type == SC_FILE_TYPE_NET || \
                 fd_dic[fd]->sc_file_type == SC_FILE_TYPE_NET_NOENC) \
                a_fetch_add(&io_cnt_net, io); \
} while (0)

#define fd_mock_enc_hash(fd, io, enc) do { \
        if (fd_dic[fd]->sc_file_type == SC_FILE_TYPE_LIB) \
                t_attest += mock_encryption(io, -1, 1); \
        else if (fd_dic[fd]->sc_file_type == SC_FILE_TYPE_TMP && !use_libtmpfs) \
                t_encrypt += mock_encryption(io, enc, 1); \
        else if (fd_dic[fd]->sc_file_type == SC_FILE_TYPE_NET && io >= HDRSIZE) \
                t_encrypt += mock_encryption(io, enc, 1); \
} while (0)

#define path_dsys_stat(pathname) do { \
        if (path_is_lib(pathname)) \
                a_fetch_add(&dsys_cnt_lib, 1); \
        else if (path_is_tmp(pathname) && !use_libtmpfs) \
                a_fetch_add(&dsys_cnt_tmp, 1); \
} while (0)

#define __fd_filter(fd) do { \
        if (fd < 0 || fd_dic[fd] == 0)                  \
                return -EBADF;                          \
        if (fd_dic[fd]->type != FD_TYPE_SC_HOST_FILE)   \
                return -EDONTHOOK;                      \
} while(0)

#define fd_filter(fd) do {                              \
        __fd_filter(fd);                                \
        if (fd_dic[fd]->host_fd < 0)                    \
                return -EBADF;                          \
        fd_dsys_stat(fd);                               \
} while(0)

#define is_libtmpfs_fd(fd) (use_libtmpfs && fd_dic[fd]->sc_file_type == SC_FILE_TYPE_TMP)
#define is_libtmpfs_path(pathname) (use_libtmpfs && path_is_tmp(pathname))

#define path_rewrite_n(pathname, n)  \
char __pathname_##n[1024]; \
do { \
        if (use_cache && path_is_cached(pathname)) { \
                strcpy(__pathname_##n, "/sc_cache"); \
                strcat(__pathname_##n, pathname); \
                pathname = __pathname_##n; \
        } \
} while (0)

#define path_rewrite(pathname) path_rewrite_n(pathname, 1)

#define CYCLE_PER_NS 1UL

#define defer_sched (__pthread_self()->sc_defer_sched)

#define dsys_begin \
struct sc_shm *shm; \
unsigned long t0, t1; \
unsigned long ta0, ta1; \
do { \
        shm = get_shm(); \
        defer_sched = 1; \
        t0 = pmu_read_real_cycle(); \
        ta0 = t_pgfault; \
} while (0)

#define dsys_end \
do {\
        ta1 = t_pgfault; \
        t1 = pmu_read_real_cycle(); \
        if (shm->req != SC_SHM_REQ_EPOLL_PWAIT || shm->ret) \
                t_delegate += (t1 - t0) / CYCLE_PER_NS - shm->time - (ta1 - ta0); \
        if (defer_sched > 1) \
                usys_yield(); \
        defer_sched = 0; \
        return shm->ret; \
} while (0)

static bool path_on_host(const char *pathname)
{
        if (!strncmp(pathname, "/sc_cache", 9)) {
                return false;
        }
        
        return true;
}

static bool path_is_cached(const char *pathname)
{
        return !strncmp(pathname, "/usr", 4) ||
               !strncmp(pathname, "/lib", 4) ||
               !strncmp(pathname, "/bin", 4) ||
               !strncmp(pathname, "/etc", 4) ||
               !strncmp(pathname, "/root", 5) ||
               !strncmp(pathname, "/func/node_modules", 18);
}

static bool path_is_lib(const char *pathname)
{
        return path_is_cached(pathname) || !strncmp(pathname, "/func", 5);
}

static bool path_is_tmp(const char *pathname)
{
        return !strncmp(pathname, "/tmp", 4);
}

static unsigned long mock_encryption(size_t size, int enc, int hash)
{
        int i, count;
        u8 digest[32];
        u8 encrypted[BLKSIZE];
        u8 decrypted[BLKSIZE];
        unsigned long t0, t1;

        count = size ? (size - 1) / BLKSIZE + 1 : 0;
        if (use_defer_encrypt && enc >= 0) {
                defer_encrypt_cnt += count * BLKSIZE;
                return 0;
        }

        defer_sched = 1;
        
        t0 = pmu_read_real_cycle();
        for (i = 0; i < count; i++) {
                if (hash)
                        sha256_update_shani(decrypted, BLKSIZE, digest);
                if (enc == 1)
                        AES_CBC_encrypt(decrypted, encrypted, iv, BLKSIZE, round_keys, AES128_Rounds);
                if (enc == 0)
                        AES_CBC_decrypt(encrypted, decrypted, iv, BLKSIZE, round_keys, AES128_Rounds);
        }
        t1 = pmu_read_real_cycle();
        
        if (defer_sched > 1)
                usys_yield();
        defer_sched = 0;

        return (t1 - t0) / CYCLE_PER_NS;
}

static void *get_shm(void)
{
        cap_t pmo_cap;
        struct sc_shm *shm = __pthread_self()->sc_shm;

        if (likely(shm)) {
                goto out;
        }

        pmo_cap = usys_create_pmo(SC_SHM_SIZE, PMO_SC_SHM);
        BUG_ON(pmo_cap < 0);
        shm = chcore_auto_map_pmo(pmo_cap, SC_SHM_SIZE, VM_READ | VM_WRITE);
        BUG_ON(!shm);
        __pthread_self()->sc_shm_cap = pmo_cap;
        __pthread_self()->sc_shm = shm;

        defer_sched = 0;
        usys_split_container(SYS_SC_OP_REG_DEFER_SCHED, (long)&defer_sched, 0, 0, 0);

out:
        if (unlikely(!__pthread_self()->sc_polling && use_polling)) {
                shm->pending = 0;
                usys_split_container(SYS_SC_OP_ADD_POLLING,
                                     __pthread_self()->sc_shm_cap, 0, 0, 0);
                __pthread_self()->sc_polling = 1;
        }

        return shm;
}

static void issue_dsys(void)
{
        unsigned t0, t1;
        struct sc_shm *shm = __pthread_self()->sc_shm;
        
        t0 = pmu_read_real_cycle();

        a_fetch_add(&dsys_cnt_all, 1);

        if (__pthread_self()->sc_polling) {
                shm->pending = 1;
                while (shm->pending);
        } else {
                usys_split_container(SYS_SC_OP_SHM_REQ,
                        __pthread_self()->sc_shm_cap, 0, 0, 0);
        }

        t1 = pmu_read_real_cycle();
        if (shm->req != SC_SHM_REQ_EPOLL_PWAIT || shm->ret)
                t_redirect += (t1 - t0) / CYCLE_PER_NS - shm->time;
}

static long __dsem_init(int pshared, unsigned value)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SEM_INIT;

        shm->sem_init.pshared = pshared;
        shm->sem_init.value = value;

        issue_dsys();

        dsys_end;
}

sem_t *dsem_init(int pshared, unsigned value)
{
        return (void *)__dsem_init(pshared, value);
}

int dsem_wait(sem_t *sem)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SEM_WAIT;

        shm->sem_wait.sem = sem;

        issue_dsys();

        dsys_end;
}

int dsem_trywait(sem_t *sem)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SEM_TRYWAIT;

        shm->sem_trywait.sem = sem;

        issue_dsys();

        dsys_end;
}

int dsem_timedwait(sem_t *sem, const struct timespec *timeout)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SEM_TIMEDWAIT;

        shm->sem_timedwait.sem = sem;

        memcpy(shm->data, timeout, sizeof(*timeout));

        issue_dsys();

        dsys_end;
}

int dsem_post(sem_t *sem)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SEM_POST;

        shm->sem_post.sem = sem;

        issue_dsys();

        dsys_end;
}

int dfutex(int *uaddr, int futex_op, int val, struct timespec *timeout,
           int *uaddr2, int val3);

long dsys_io_uring_enter(int fd, unsigned int to_submit,
                                  unsigned int min_complete, unsigned int flags)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_IO_URING_ENTER;

        shm->io_uring_enter.fd = fd;
        shm->io_uring_enter.to_submit = to_submit;
        shm->io_uring_enter.min_complete = min_complete;
        shm->io_uring_enter.flags = flags;

        issue_dsys();

        dsys_end;
}

long dsys_writev(int fd, const struct iovec *iov, int iovcnt)
{
        int i;
        unsigned long n;
        unsigned long offset = 0;
        unsigned long remain = SC_SHM_MAX_DATA_LEN;
        dsys_begin;
        
        shm->req = SC_SHM_REQ_WRITE;
        
        shm->write.fd = fd;

        for (i = 0; i < iovcnt && remain; i++) {
                n = MIN(remain, iov[i].iov_len);
                memcpy(shm->data + offset, iov[i].iov_base, n);
                offset += n;
                remain -= n;
        }
        shm->write.count = offset;

        issue_dsys();

        dsys_end;
}

long dsys_open(const char *pathname, int flags, mode_t mode)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_OPEN;

        shm->open.flags = flags;
        shm->open.mode = mode;

        BUG_ON(strlen(pathname) >= SC_SHM_MAX_DATA_LEN);
        strcpy(shm->data, pathname);

        issue_dsys();

        dsys_end;
}

long dsys_read(int fd, void *buf, size_t count)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_READ;

        shm->read.fd = fd;
        shm->read.count = MIN(count, SC_SHM_MAX_DATA_LEN);

        issue_dsys();

        if (shm->ret > 0) {
                memcpy(buf, shm->data, shm->ret);
        }

        dsys_end;
}

long dsys_pread(int fd, void *buf, size_t count, off_t offset)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_PREAD;

        shm->pread.fd = fd;
        shm->pread.count = MIN(count, SC_SHM_MAX_DATA_LEN);
        shm->pread.offset = offset;

        issue_dsys();

        if (shm->ret > 0) {
                memcpy(buf, shm->data, shm->ret);
        }

        dsys_end;
}

long dsys_lseek(int fd, off_t offset, int whence)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_LSEEK;

        shm->lseek.fd = fd;
        shm->lseek.offset = offset;
        shm->lseek.whence = whence;

        issue_dsys();

        dsys_end;
}

long dsys_stat(const char *pathname, struct stat *statbuf)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_STAT;

        BUG_ON(strlen(pathname) >= SC_SHM_MAX_DATA_LEN);
        strcpy(shm->data, pathname);

        issue_dsys();

        if (!shm->ret) {
                memcpy(statbuf, shm->data, sizeof(*statbuf));
        }

        dsys_end;
}

long dsys_lstat(const char *pathname, struct stat *statbuf)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_LSTAT;

        BUG_ON(strlen(pathname) >= SC_SHM_MAX_DATA_LEN);
        strcpy(shm->data, pathname);

        issue_dsys();

        if (!shm->ret) {
                memcpy(statbuf, shm->data, sizeof(*statbuf));
        }

        dsys_end;
}

long dsys_getdents64(int fd, void *dirp, size_t count)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_GETDENTS64;

        shm->getdents64.fd = fd;
        shm->getdents64.count = MIN(count, SC_SHM_MAX_DATA_LEN);

        issue_dsys();

        if (shm->ret > 0) {
                memcpy(dirp, shm->data, shm->ret);
        }

        dsys_end;
}

long dsys_fstat(int fd, struct stat *statbuf)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_FSTAT;

        shm->fstat.fd = fd;

        issue_dsys();

        if (!shm->ret) {
                memcpy(statbuf, shm->data, sizeof(*statbuf));
        }

        dsys_end;
}

long dsys_rename(const char *oldpath, const char *newpath)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_RENAME;
        
        shm->rename.oldpath = 0;
        shm->rename.newpath = strlen(oldpath) + 1;
        BUG_ON(shm->rename.newpath + strlen(newpath) >=
               SC_SHM_MAX_DATA_LEN);
        strcpy(shm->data, oldpath);
        strcpy(shm->data + shm->rename.newpath, newpath);

        issue_dsys();

        dsys_end;
}

long dsys_close(int fd)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_CLOSE;

        shm->close.fd = fd;

        issue_dsys();

        dsys_end;
}

long dsys_fcntl(int fd, int cmd, long arg)
{
        dsys_begin;
        
        BUG_ON(cmd != F_GETFD && cmd != F_SETFD && cmd != F_GETFL && cmd != F_SETFL);

        shm->req = SC_SHM_REQ_FCNTL;

        shm->fcntl.fd = fd;
        shm->fcntl.cmd = cmd;
        shm->fcntl.arg = arg;

        issue_dsys();

        dsys_end;
}

long dsys_ioctl(int fd, unsigned long request, void *argp)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_IOCTL;

        shm->ioctl.fd = fd;
        shm->ioctl.request = request;

        switch (request) {
        case TIOCGWINSZ:
                /* nothing */
                break;
        case FIOCLEX:
                /* nothing */
                break;
        case TCGETS:
                /* nothing */
                break;
        case TCSETS:
                memcpy(shm->data, argp, sizeof(struct termios));
                break;
        case FIONBIO:
                memcpy(shm->data, argp, sizeof(int));
                break;
        default:
                // BUG_ON(1);
                break;
        };

        issue_dsys();

        if (shm->ret < 0) {
                dsys_end;
        }

        switch (request) {
        case TIOCGWINSZ:
                memcpy(argp, shm->data, sizeof(struct winsize));
                break;
        case TCGETS:
                memcpy(argp, shm->data, sizeof(struct termios));
                break;
        default:
                break;
        };

        dsys_end;
}

long dsys_readlink(const char *pathname, char *buf, size_t bufsiz)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_READLINK;

        shm->readlink.bufsiz = MIN(bufsiz, SC_SHM_MAX_DATA_LEN);

        BUG_ON(strlen(pathname) >= SC_SHM_MAX_DATA_LEN);
        strcpy(shm->data, pathname);

        issue_dsys();

        if (shm->ret > 0) {
                memcpy(buf, shm->data, shm->ret);
        }

        dsys_end;
}

long dsys_readv(int fd, struct iovec *iov, int iovcnt)
{
        int i;
        size_t n, count;
        dsys_begin;

        shm->req = SC_SHM_REQ_READ;

        shm->read.fd = fd;
        
        count = 0;
        for (i = 0; i < iovcnt; i++) {
                count += iov[i].iov_len;
        }
        shm->read.count = MIN(count, SC_SHM_MAX_DATA_LEN);

        issue_dsys();

        count = 0;
        for (i = 0; i < iovcnt && count < shm->ret; i++) {
                n = MIN(shm->ret - count, iov[i].iov_len);
                memcpy(iov[i].iov_base, shm->data + count, n);
                count += n;
        }

        dsys_end;
}

long dsys_write(int fd, const void *buf, size_t count)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_WRITE;

        shm->write.fd = fd;
        shm->write.count = MIN(count, SC_SHM_MAX_DATA_LEN);

        memcpy(shm->data, buf, shm->write.count);

        issue_dsys();

        dsys_end;
}

long dsys_mkdir(const char *pathname, mode_t mode)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_MKDIR;

        shm->mkdir.mode = mode;

        BUG_ON(strlen(pathname) >= SC_SHM_MAX_DATA_LEN);
        strcpy(shm->data, pathname);

        issue_dsys();

        dsys_end;
}

long dsys_epoll_create1(int flags)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_EPOLL_CREATE1;

        shm->epoll_create1.flags = flags;

        issue_dsys();

        dsys_end;
}

long dsys_sched_getaffinity(pid_t pid, size_t cpusetsize,
                                     cpu_set_t *mask)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SCHED_GETAFFINITY;

        shm->sched_getaffinity.pid = pid;
        shm->sched_getaffinity.cpusetsize = cpusetsize;
        
        BUG_ON(cpusetsize > SC_SHM_MAX_DATA_LEN);

        issue_dsys();

        if (shm->ret > 0) {
                memcpy(mask, shm->data, shm->ret);
        }
        
        dsys_end;
}

long dsys_epoll_pwait(int epfd, struct epoll_event *events,
                               int maxevents, int timeout,
                               const sigset_t *__sigmask)
{
        dsys_begin;

        BUG_ON(maxevents * sizeof(*events) > SC_SHM_MAX_DATA_LEN);

        shm->req = SC_SHM_REQ_EPOLL_PWAIT;

        shm->epoll_pwait.epfd = epfd;
        shm->epoll_pwait.maxevents = maxevents;
        shm->epoll_pwait.timeout = timeout;

        BUG_ON(__sigmask != NULL);

        issue_dsys();

        if (shm->ret > 0) {
                memcpy(events, shm->data, shm->ret * sizeof(*events));
        }

        dsys_end;
}

long dsys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_EPOLL_CTL;

        shm->epoll_ctl.epfd = epfd;
        shm->epoll_ctl.op = op;
        shm->epoll_ctl.fd = fd;

        memcpy(shm->data, event, sizeof(*event));

        issue_dsys();

        dsys_end;
}

long dsys_pipe2(int pipefd[2], int flags)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_PIPE2;

        shm->pipe2.flags = flags;

        issue_dsys();

        if (!shm->ret) {
                pipefd[0] = shm->pipe2.pipefd[0];
                pipefd[1] = shm->pipe2.pipefd[1];
        }

        dsys_end;
}

long dsys_eventfd2(unsigned int initval, int flags)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_EVENTFD2;

        shm->eventfd2.initval = initval;
        shm->eventfd2.flags = flags;

        issue_dsys();

        dsys_end;
}

typedef struct __user_cap_header_struct {
	u32 padding[2];
} *cap_user_header_t;

typedef struct __user_cap_data_struct {
        u32 padding[3];
} *cap_user_data_t;

long dsys_capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_CAPGET;

        memcpy(shm->data, hdrp, sizeof(*hdrp));

        issue_dsys();

        if (!shm->ret) {
                memcpy(datap, shm->data, sizeof(*datap));
        }

        dsys_end;
}

long dsys_dup3(int oldfd, int newfd, int flags)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_DUP3;

        shm->dup3.oldfd = oldfd;
        shm->dup3.newfd = newfd;
        shm->dup3.flags = flags;

        issue_dsys();

        dsys_end;
}

struct statx {
	char padding[0x100];
};

long dsys_statx(int dirfd, const char *pathname, int flags,
                  unsigned int mask, struct statx *statxbuf)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_STATX;

        shm->statx.dirfd = dirfd;
        shm->statx.flags = flags;
        shm->statx.mask = mask;

        BUG_ON(strlen(pathname) >= SC_SHM_MAX_DATA_LEN);
        strcpy(shm->data, pathname);

        issue_dsys();

        if (!shm->ret) {
                memcpy(statxbuf, shm->data, sizeof(*statxbuf));
        }

        dsys_end;
}

long dsys_socket(int domain, int type, int protocol)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SOCKET;

        shm->socket.domain = domain;
        shm->socket.type = type;
        shm->socket.protocol = protocol;

        issue_dsys();

        dsys_end;
}

long dsys_bind(int sockfd, const struct sockaddr *addr,
                        socklen_t addrlen)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_BIND;

        shm->bind.sockfd = sockfd;
        shm->bind.addrlen = addrlen;

        BUG_ON(addrlen > SC_SHM_MAX_DATA_LEN);
        memcpy(shm->data, addr, addrlen);

        issue_dsys();

        dsys_end;
}

long dsys_sendto(int sockfd, const void *buf, size_t len, int flags,
                          const struct sockaddr *dest_addr, socklen_t addrlen)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SENDTO;

        shm->sendto.sockfd = sockfd;
        shm->sendto.len = len;
        shm->sendto.flags = flags;
        shm->sendto.addrlen = addrlen;

        BUG_ON(addrlen >= SC_SHM_MAX_DATA_LEN);
        shm->sendto.len = MIN(len, SC_SHM_MAX_DATA_LEN - addrlen);
        memcpy(shm->data, dest_addr, addrlen);
        memcpy(shm->data + addrlen, buf, shm->sendto.len);

        issue_dsys();

        dsys_end;
}

long dsys_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_POLL;

        shm->poll.nfds = nfds;
        shm->poll.timeout = timeout;

        BUG_ON(nfds * sizeof(*fds) >= SC_SHM_MAX_DATA_LEN);
        memcpy(shm->data, fds, nfds * sizeof(*fds));

        issue_dsys();

        if (shm->ret > 0) {
                memcpy(fds, shm->data, nfds * sizeof(*fds));
        }

        dsys_end;
}

long dsys_recvfrom(int sockfd, void *buf, size_t len, int flags,
                            struct sockaddr *src_addr, socklen_t *addrlen)
{
        dsys_begin;
        socklen_t __zero = 0;

        if (src_addr == NULL) {
                addrlen = &__zero;
        }

        shm->req = SC_SHM_REQ_RECVFROM;

        shm->recvfrom.sockfd = sockfd;
        shm->recvfrom.flags = flags;
        shm->recvfrom.addrlen = *addrlen;

        BUG_ON(*addrlen >= SC_SHM_MAX_DATA_LEN);
        shm->recvfrom.len = MIN(len, SC_SHM_MAX_DATA_LEN - *addrlen);

        issue_dsys();

        if (shm->ret > 0) {
                memcpy(src_addr, shm->data, shm->recvfrom.addrlen);
                memcpy(buf, shm->data + *addrlen, shm->ret);
                *addrlen = shm->recvfrom.addrlen;
        }

        dsys_end;
}

long dsys_connect(int sockfd, const struct sockaddr *addr,
                           socklen_t addrlen)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_CONNECT;

        shm->connect.sockfd = sockfd;
        shm->connect.addrlen = addrlen;

        BUG_ON(addrlen > SC_SHM_MAX_DATA_LEN);
        memcpy(shm->data, addr, addrlen);

        issue_dsys();

        dsys_end;
}

long dsys_setsockopt(int sockfd, int level, int optname,
                              const void *optval, socklen_t optlen)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SETSOCKOPT;

        shm->setsockopt.sockfd = sockfd;
        shm->setsockopt.level = level;
        shm->setsockopt.optname = optname;
        shm->setsockopt.optlen = optlen;

        BUG_ON(optlen > SC_SHM_MAX_DATA_LEN);
        memcpy(shm->data, optval, optlen);

        issue_dsys();

        dsys_end;
}

long dsys_shutdown(int sockfd, int how)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SHUTDOWN;

        shm->shutdown.sockfd = sockfd;
        shm->shutdown.how = how;

        issue_dsys();

        dsys_end;
}

long dsys_getcwd(char *buf, size_t size)
{
        dsys_begin;

        BUG_ON(size > SC_SHM_MAX_DATA_LEN);

        shm->req = SC_SHM_REQ_GETCWD;

        shm->getcwd.size = size;

        issue_dsys();

        if (shm->ret) {
                strcpy(buf, shm->data);
        }

        dsys_end;
}

long dsys_access(const char *pathname, int mode)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_ACCESS;

        shm->access.mode = mode;

        BUG_ON(strlen(pathname) >= SC_SHM_MAX_DATA_LEN);
        strcpy(shm->data, pathname);

        issue_dsys();

        dsys_end;
}

struct sched_attr {
        u64 padding[7];
};

long dsys_sched_setattr(pid_t pid, struct sched_attr *attr,
                                 unsigned int flags)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SCHED_SETATTR;

        shm->sched_setattr.pid = pid;
        shm->sched_setattr.flags = flags;

        memcpy(shm->data, attr, sizeof(*attr));

        issue_dsys();

        dsys_end;
}

long dsys_sched_getattr(pid_t pid, struct sched_attr *attr,
                                 unsigned int size, unsigned int flags)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SCHED_GETATTR;

        shm->sched_getattr.pid = pid;
        shm->sched_getattr.size = size;
        shm->sched_getattr.flags = flags;

        issue_dsys();

        if (!shm->ret) {
                memcpy(attr, shm->data, sizeof(*attr));
        }

        dsys_end;
}

long dsys_ftruncate(int fd, off_t length)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_FTRUNCATE;

        shm->ftruncate.fd = fd;
        shm->ftruncate.length = length;

        issue_dsys();

        dsys_end;
}

long dsys_umask(mode_t mask)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_UMASK;

        shm->umask.mask = mask;

        issue_dsys();

        dsys_end;
}

long dsys_unlink(const char *pathname)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_UNLINK;

        BUG_ON(strlen(pathname) >= SC_SHM_MAX_DATA_LEN);
        strcpy(shm->data, pathname);

        issue_dsys();

        dsys_end;
}

long dsys_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
        dsys_begin;

        BUG_ON(*addrlen >= SC_SHM_MAX_DATA_LEN);

        shm->req = SC_SHM_REQ_GETSOCKNAME;

        shm->getsockname.sockfd = sockfd;
        shm->getsockname.addrlen = *addrlen;

        issue_dsys();

        if (!shm->ret) {
                *addrlen = shm->getsockname.addrlen;
                memcpy(addr, shm->data, *addrlen);
        }

        dsys_end;
}

long dsys_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
        dsys_begin;

        BUG_ON(*addrlen >= SC_SHM_MAX_DATA_LEN);

        shm->req = SC_SHM_REQ_GETPEERNAME;

        shm->getpeername.sockfd = sockfd;
        shm->getpeername.addrlen = *addrlen;

        issue_dsys();

        if (!shm->ret) {
                *addrlen = shm->getpeername.addrlen;
                memcpy(addr, shm->data, *addrlen);
        }

        dsys_end;
}

long dsys_getsockopt(int sockfd, int level, int optname,
                              void *optval, socklen_t *optlen)
{
        dsys_begin;

        BUG_ON(*optlen >= SC_SHM_MAX_DATA_LEN);

        shm->req = SC_SHM_REQ_GETSOCKOPT;

        shm->getsockopt.sockfd = sockfd;
        shm->getsockopt.level = level;
        shm->getsockopt.optname = optname;
        shm->getsockopt.optlen = *optlen;

        issue_dsys();

        if (!shm->ret) {
                *optlen = shm->getsockopt.optlen;
                memcpy(optval, shm->data, *optlen);
        }

        dsys_end;
}

long dsys_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_CLOCK_GETTIME;

        shm->clock_gettime.clk_id = clk_id;

        issue_dsys();

        if (!shm->ret) {
                memcpy(tp, shm->data, sizeof(*tp));
        }

        dsys_end;
}

long dsys_sched_setaffinity(pid_t pid, size_t cpusetsize,
                                     cpu_set_t *mask)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SCHED_SETAFFINITY;

        shm->sched_setaffinity.pid = pid;
        shm->sched_setaffinity.cpusetsize = cpusetsize;
        
        BUG_ON(cpusetsize > SC_SHM_MAX_DATA_LEN);
        memcpy(shm->data, mask, cpusetsize);

        issue_dsys();

        dsys_end;
}

long dsys_clock_getres(clockid_t clk_id, struct timespec *tp)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_CLOCK_GETRES;

        shm->clock_getres.clk_id = clk_id;

        issue_dsys();

        if (!shm->ret) {
                memcpy(tp, shm->data, sizeof(*tp));
        }

        dsys_end;
}

long dsys_sysinfo(struct sysinfo *info)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SYSINFO;

        issue_dsys();

        if (!shm->ret) {
                memcpy(info, shm->data, sizeof(*info));
        }

        dsys_end;
}

long dsys_listen(int sockfd, int backlog)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_LISTEN;

        shm->listen.sockfd = sockfd;
        shm->listen.backlog = backlog;

        issue_dsys();

        dsys_end;
}

long dsys_accept4(int sockfd, struct sockaddr *addr,
                           socklen_t *addrlen, int flags)
{
        dsys_begin;

        BUG_ON(!addr || !addrlen);
        BUG_ON(*addrlen > SC_SHM_MAX_DATA_LEN);

        shm->req = SC_SHM_REQ_ACCEPT4;

        shm->accpet4.sockfd = sockfd;
        shm->accpet4.addrlen = *addrlen;
        shm->accpet4.flags = flags;

        issue_dsys();

        if (shm->ret > 0) {
                *addrlen = shm->accpet4.addrlen;
                memcpy(addr, shm->data, *addrlen);
        }

        dsys_end;
}

long dsys_setitimer(int which, const struct itimerval *new_value,
                             struct itimerval *old_value)
{
        dsys_begin;

        BUG_ON(!new_value || old_value);

        shm->req = SC_SHM_REQ_SETITIMER;

        shm->setitimer.which = which;
        memcpy(shm->data, new_value, sizeof(*new_value));

        issue_dsys();

        dsys_end;
}

long dsys_chmod(const char *pathname, mode_t mode)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_CHMOD;

        shm->chmod.mode = mode;

        BUG_ON(strlen(pathname) >= SC_SHM_MAX_DATA_LEN);
        strcpy(shm->data, pathname);

        issue_dsys();

        dsys_end;
}

long dsys_times(struct tms *buf)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_TIMES;

        memcpy(shm->data, buf, sizeof(*buf));

        issue_dsys();

        dsys_end;
}

long dsys_getuid(void)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_GETUID;

        issue_dsys();

        dsys_end;
}

long dsys_geteuid(void)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_GETEUID;

        issue_dsys();

        dsys_end;
}

long dsys_getgid(void)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_GETGID;

        issue_dsys();

        dsys_end;
}

long dsys_getegid(void)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_GETEGID;

        issue_dsys();

        dsys_end;
}

long dsys_setuid(uid_t uid)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SETUID;

        shm->setuid.uid = uid;

        issue_dsys();

        dsys_end;
}

long dsys_setgid(gid_t gid)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SETGID;

        shm->setgid.gid = gid;

        issue_dsys();

        dsys_end; 
}

long dsys_getgroups(int size, gid_t list[])
{
        dsys_begin;

        BUG_ON(size * sizeof(gid_t) > SC_SHM_MAX_DATA_LEN);

        shm->req = SC_SHM_REQ_GETGROUPS;

        shm->getgroups.size = size;

        issue_dsys();

        if (shm->ret > 0) {
                memcpy(list, shm->data, shm->ret * sizeof(gid_t));
        }

        dsys_end; 
}

long dsys_setgroups(size_t size, const gid_t *list)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_SETGROUPS;

        shm->setgroups.size = size;

        BUG_ON(size * sizeof(gid_t) > SC_SHM_MAX_DATA_LEN);
        memcpy(shm->data, list, size * sizeof(gid_t));

        issue_dsys();

        dsys_end; 
}

long dsys_getpid(void)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_GETPID;

        issue_dsys();

        dsys_end; 
}

long dsys_dup2(int oldfd, int newfd)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_DUP2;

        shm->dup2.oldfd = oldfd;
        shm->dup2.newfd = newfd;

        issue_dsys();

        dsys_end;
}

long dsys_rt_sigtimedwait(const sigset_t *set, siginfo_t *info,
                                   const struct timespec *timeout,
                                   size_t sigsetsize)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_RT_SIGTIMEDWAIT;

        shm->rt_sigtimedwait.sigsetsize = sigsetsize;

        BUG_ON(timeout != NULL);
        memcpy(shm->data, set, sizeof(*set));

        issue_dsys();

        if (shm->ret >= 0) {
                memcpy(info, shm->data, sizeof(*info));
        }

        dsys_end;
}

long dsys_dup(int oldfd)
{
        dsys_begin;

        shm->req = SC_SHM_REQ_DUP;

        shm->dup.oldfd = oldfd;

        issue_dsys();

        dsys_end;
}

long dsys_select(int nfds, fd_set *readfds, fd_set *writefds,
                 fd_set *exceptfds, struct timeval *timeout)
{
        dsys_begin;

        BUG_ON(!readfds || !writefds || exceptfds || timeout);

        shm->req = SC_SHM_REQ_SELECT;

        shm->select.nfds = nfds;

        memcpy(shm->data, readfds, sizeof(*readfds));
        memcpy(shm->data + sizeof(*readfds), writefds, sizeof(*writefds));

        issue_dsys();

        memcpy(readfds, shm->data, sizeof(*readfds));
        memcpy(writefds, shm->data + sizeof(*readfds), sizeof(*writefds));

        dsys_end;
}

static long sc_sys_open(const char *pathname, int flags, mode_t mode)
{
        int fd, host_fd;

        path_rewrite(pathname);
        if (!path_on_host(pathname)) {
                return chcore_openat(AT_FDCWD, pathname, flags, mode);
        }

        if (strstr(pathname, "orcexec") ||
            strstr(pathname, "/dev/pts") ||
            strstr(pathname, "/dev/null") ||
            !strcmp(pathname, "/")) {
                return -EPERM;
        }

        if ((fd = alloc_fd()) < 0)
                return fd;

        if (is_libtmpfs_path(pathname)){
                host_fd = libtmpfs_open(pathname, flags, mode);
        } else {
                path_dsys_stat(pathname);
                host_fd = dsys_open(pathname, flags, mode);
        }

        if (host_fd < 0) {
                free_fd(fd);
                fd = host_fd;
        } else {
                fd_dic[fd]->type = FD_TYPE_SC_HOST_FILE;
                fd_dic[fd]->host_fd = host_fd;
                if (path_is_lib(pathname)) {
                        fd_dic[fd]->sc_file_type = SC_FILE_TYPE_LIB;
                } else if (path_is_tmp(pathname)) {
                        fd_dic[fd]->sc_file_type = SC_FILE_TYPE_TMP;
                } else {
                        fd_dic[fd]->sc_file_type = 0;
                }
        }

        return fd;
}

long sc_sys_ioctl(int fd, unsigned long request, void *argp)
{
        fd_filter(fd);

        if (is_libtmpfs_fd(fd)) {
                return -ENOSYS;
        }

        return dsys_ioctl(fd_dic[fd]->host_fd, request, argp);
}

long sc_sys_writev(int fd, const struct iovec *iov, int iovcnt)
{
        int ret;
        
        fd_filter(fd);

        if (is_libtmpfs_fd(fd)) {
                return libtmpfs_writev(fd_dic[fd]->host_fd, iov, iovcnt);
        }

        ret = dsys_writev(fd_dic[fd]->host_fd, iov, iovcnt);
        if (ret > 0) {
                fd_mock_enc_hash(fd, ret, 1);
                fd_io_stat(fd, ret);
        }

        return ret;
}

long sc_sys_read(int fd, void *buf, size_t count)
{
        int ret;
        
        fd_filter(fd);
        
        if (is_libtmpfs_fd(fd)) {
                return libtmpfs_read(fd_dic[fd]->host_fd, buf, count);
        }

        ret = dsys_read(fd_dic[fd]->host_fd, buf, count);
        if (ret > 0) {
                fd_mock_enc_hash(fd, ret, 0);
                fd_io_stat(fd, ret);
        }

        return ret;
}

static long sc_sys_mmap(void *addr, size_t len, int prot, int flags, int fd,
                        off_t off)
{
        int ret;
        size_t n;

        if (fd < 0)
                return -EDONTHOOK;

        fd_filter(fd);

        addr = chcore_mmap(addr, len, prot | PROT_WRITE, flags, -1, 0);
        if (addr == MAP_FAILED) {
                return (long)addr;
        }

        n = 0;
        while (n < len) {
                ret = dsys_pread(fd_dic[fd]->host_fd, (char *)addr + n, len - n, off + n);
                if (ret == 0) {
                        memset((char *)addr + n, 0, len - n);
                        break;
                } else if (ret < 0) {
                        chcore_munmap(addr, len);
                        return (long)MAP_FAILED;
                } else {
                        fd_io_stat(fd, ret);
                        n += ret;
                }
        }

        mprotect(addr, len, prot);

        fd_mock_enc_hash(fd, len, -1);

        if (prot & PROT_EXEC) {
                usys_cache_flush((unsigned long)addr, len, SYNC_IDCACHE);
        }

        return (long)addr;
}

long sc_sys_close(int fd)
{
        int ret;

        __fd_filter(fd);

        if (is_libtmpfs_fd(fd)) {
                ret = libtmpfs_close(fd_dic[fd]->host_fd);
                if (ret < 0) {
                        return ret;
                }
        } else if (fd_dic[fd]->sc_file_type == SC_FILE_TYPE_EPOLL) {
                if (fd_dic[fd]->fd != -1) {
                        BUG_ON(chcore_close(fd_dic[fd]->fd));
                }
                if (fd_dic[fd]->host_fd != -1) {
                        fd_dsys_stat(fd);
                        BUG_ON(dsys_close(fd_dic[fd]->host_fd));
                }
                free(fd_dic[fd]->private_data);
        } else {
                fd_dsys_stat(fd);
                ret = dsys_close(fd_dic[fd]->host_fd);
                if (ret < 0) {
                        return ret;
                }
        }

        free_fd(fd);
        return 0;
}

long sc_sys_fcntl(int fd, int cmd, long arg)
{
        fd_filter(fd);

        if (is_libtmpfs_fd(fd)) {
                BUG_ON(cmd != F_SETFD);
                return 0;
        }

        return dsys_fcntl(fd_dic[fd]->host_fd, cmd, arg);
}

long sc_sys_fstat(int fd, struct stat *statbuf)
{
        fd_filter(fd);

        if (is_libtmpfs_fd(fd)) {
                return libtmpfs_fstat(fd_dic[fd]->host_fd, statbuf);
        }

        return dsys_fstat(fd_dic[fd]->host_fd, statbuf);
}

long sc_sys_readlink(const char *pathname, char *buf, size_t bufsiz)
{
        path_rewrite(pathname);
        if (!path_on_host(pathname)) {
                return chcore_readlinkat(AT_FDCWD, pathname, buf, bufsiz);
        }
        
        if (is_libtmpfs_path(pathname)) {
                BUG_ON(1);
        }

        path_dsys_stat(pathname);
        return dsys_readlink(pathname, buf, bufsiz);
}

extern int __xstatxx(int req, int fd, const char *path, int flags,
                     void *statbuf, size_t bufsize);

long sc_sys_clock_gettime(clockid_t clk_id, struct timespec *tp);

long sc_sys_stat(const char *pathname, struct stat *statbuf)
{
        path_rewrite(pathname);
        if (!path_on_host(pathname)) {
                return __xstatxx(FS_REQ_FSTATAT,
                                 AT_FDCWD, /* dirfd */
                                 pathname, /* path  */
                                 0, /* flags */
                                 statbuf, /* statbuf */
                                 sizeof(struct stat));
        }
        
        if (is_libtmpfs_path(pathname)) {
                return libtmpfs_fstatat(-101, pathname, statbuf, 0);
        }

        path_dsys_stat(pathname);
        return dsys_stat(pathname, statbuf);
}

long sc_sys_getdents64(int fd, void *dirp, size_t count)
{
        fd_filter(fd);

        if (is_libtmpfs_fd(fd)) {
                return libtmpfs_getdents64(fd_dic[fd]->host_fd, dirp, count);
        }

        return dsys_getdents64(fd_dic[fd]->host_fd, dirp, count);
}

long sc_sys_write(int fd, const void *buf, size_t count)
{
        int ret;

        fd_filter(fd);

        if (is_libtmpfs_fd(fd)) {
                return libtmpfs_write(fd_dic[fd]->host_fd, buf, count);
        }

        ret = dsys_write(fd_dic[fd]->host_fd, buf, count);
        if (ret > 0) {
                fd_mock_enc_hash(fd, ret, 1);
                fd_io_stat(fd, ret);
        }

        return ret;
}

long sc_sys_lseek(int fd, off_t offset, int whence)
{
        fd_filter(fd);                    
        
        if (is_libtmpfs_fd(fd)) {
                return libtmpfs_lseek(fd_dic[fd]->host_fd, offset, whence);
        }

        return dsys_lseek(fd_dic[fd]->host_fd, offset, whence);
}

long sc_sys_rename(const char *oldpath, const char *newpath)
{
        path_rewrite_n(oldpath, 1);
        path_rewrite_n(newpath, 2);
        if (!path_on_host(oldpath)) {
                BUG_ON(path_on_host(newpath));
                return chcore_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
        }

        if (is_libtmpfs_path(oldpath)) {
                BUG_ON(!is_libtmpfs_path(newpath));
                return libtmpfs_rename(oldpath, newpath);
        }

        path_dsys_stat(oldpath);
        return dsys_rename(oldpath, newpath);
}

long sc_sys_mkdir(const char *pathname, mode_t mode)
{
        path_rewrite(pathname);
        if (!path_on_host(pathname)) {
                return chcore_mkdirat(AT_FDCWD, pathname, mode);
        }

        if (is_libtmpfs_path(pathname)) {
                return libtmpfs_mkdir(pathname, mode);
        }

        path_dsys_stat(pathname);
        return dsys_mkdir(pathname, mode);
}

long sc_sys_readv(int fd, struct iovec *iov, int iovcnt)
{
        int ret;
        
        fd_filter(fd);

        if (is_libtmpfs_fd(fd)) {
                return libtmpfs_readv(fd_dic[fd]->host_fd, iov, iovcnt);
        }

        ret = dsys_readv(fd_dic[fd]->host_fd, iov, iovcnt);
        if (ret > 0) {
                fd_mock_enc_hash(fd, ret, 0);
                fd_io_stat(fd, ret);
        }

        return ret;
}

#define MAX_SC_EPOLL_NFDS 64
struct sc_epoll {
        int fds[MAX_SC_EPOLL_NFDS];
};

void sc_epoll_update_fd(int epfd, int op, int fd)
{
        int i;
        struct sc_epoll *sc_epoll = fd_dic[epfd]->private_data;

        if (op == EPOLL_CTL_ADD) {
                for (i = 0; i < MAX_SC_EPOLL_NFDS; i++) {
                        if (sc_epoll->fds[i] == -1) {
                                sc_epoll->fds[i] = fd;
                                return;
                        }
                }
        } else if (op == EPOLL_CTL_DEL) {
                for (i = 0; i < MAX_SC_EPOLL_NFDS; i++) {
                        if (sc_epoll->fds[i] == fd) {
                                sc_epoll->fds[i] = -1;
                                return;
                        }
                }
        } else {
                return;
        }

        BUG_ON(1);
}

int sc_epoll_find_fd(int epfd, int host_fd)
{
        int fd, i;
        struct sc_epoll *sc_epoll = fd_dic[epfd]->private_data;

        for (i = 0; i < MAX_SC_EPOLL_NFDS; i++) {
                fd = sc_epoll->fds[i];
                if (fd_dic[fd] &&
                    fd_dic[fd]->type == FD_TYPE_SC_HOST_FILE &&
                    fd_dic[fd]->host_fd == host_fd) {
                        return fd;
                }
        }

        return -1;
}

long sc_sys_epoll_create1(int flags)
{
        int fd;
        struct sc_epoll *sc_epoll;

        if ((fd = alloc_fd()) < 0)
                return fd;

        fd_dic[fd]->type = FD_TYPE_SC_HOST_FILE;
        fd_dic[fd]->fd = -1;
        fd_dic[fd]->host_fd = -1;
        fd_dic[fd]->flags = flags;
        fd_dic[fd]->sc_file_type = SC_FILE_TYPE_EPOLL;
        
        sc_epoll = malloc(sizeof(struct sc_epoll));
        BUG_ON(!sc_epoll);
        memset(sc_epoll->fds, -1, sizeof(sc_epoll->fds));
        fd_dic[fd]->private_data = sc_epoll;

        return fd;
}

void epfd_lazy_alloc(int epfd, int fd)
{        
        if (fd < 0 || !fd_dic[fd] || epfd < 0 || !fd_dic[epfd]) {
                return;
        }

        if (fd_dic[epfd]->type != FD_TYPE_SC_HOST_FILE ||
            fd_dic[epfd]->sc_file_type != SC_FILE_TYPE_EPOLL) {
                return;
        }

        if (fd_dic[epfd]->host_fd == -1 &&
            fd_dic[fd]->type == FD_TYPE_SC_HOST_FILE) {
                fd_dsys_stat(epfd);
                fd_dic[epfd]->host_fd = dsys_epoll_create1(fd_dic[epfd]->flags);
                BUG_ON(fd_dic[epfd]->host_fd < 0);
        }
        
        if (fd_dic[epfd]->fd == -1 &&
            fd_dic[fd]->type != FD_TYPE_SC_HOST_FILE) {
                fd_dic[epfd]->fd = chcore_epoll_create1(fd_dic[epfd]->flags);
                BUG_ON(fd_dic[epfd]->fd < 0);
        }
}

long sc_sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
        int ret;
        struct epoll_event _event;

        if (op == EPOLL_CTL_ADD) {
                epfd_lazy_alloc(epfd, fd);
        }

        __fd_filter(epfd);
        if (fd_dic[epfd]->sc_file_type != SC_FILE_TYPE_EPOLL) {
                return -EBADF;
        }

        if (fd_dic[fd] == 0) {
                return -EBADF;
        } else if (fd_dic[fd]->type == FD_TYPE_SC_HOST_FILE) {
                fd_dsys_stat(epfd);
                _event = *event;
                _event.data.fd = fd_dic[fd]->host_fd;
                a_fetch_add(&dsys_cnt_net, 1);
                ret = dsys_epoll_ctl(fd_dic[epfd]->host_fd, op, fd_dic[fd]->host_fd, &_event);
                if (!ret) {
                        sc_epoll_update_fd(epfd, op, fd);
                }
                return ret;
        } else {
                return chcore_epoll_ctl(fd_dic[epfd]->fd, op, fd, event);
        }
}

long sc_sys_epoll_pwait(int epfd, struct epoll_event *events,
                               int maxevents, int timeout,
                               const sigset_t *sigmask)
{
        int n, m, i;
        
        __fd_filter(epfd);
        if (fd_dic[epfd]->sc_file_type != SC_FILE_TYPE_EPOLL) {
                return -EBADF;
        }

        if (fd_dic[epfd]->host_fd == -1) {
                return fd_dic[epfd]->fd == -1 ? 0 :
                        chcore_epoll_pwait(fd_dic[epfd]->fd, events, maxevents, timeout, sigmask);
        }

        n = m = 0;
        for (;;) {
                if (fd_dic[epfd]->fd != -1) {
                        n = chcore_epoll_pwait(
                                fd_dic[epfd]->fd, events, maxevents, 0, sigmask);
                        BUG_ON(n < 0);
                }
                if (n == 0 && fd_dic[epfd]->host_fd != -1) {
                        a_fetch_add(&dsys_cnt_net, 1);
                        m = dsys_epoll_pwait(
                                fd_dic[epfd]->host_fd, events + n, maxevents - n, 0, sigmask);
                        BUG_ON(m < 0);
                }
                if (n + m == 0 && timeout) {
                        usys_yield();
                } else {
                        break;
                }
        }

        for (i = n; i < n + m; i++) {
                events[i].data.fd = sc_epoll_find_fd(epfd, events[i].data.fd);
                BUG_ON(events[i].data.fd < 0);
        }

        return n + m;
}

long sc_sys_socket(int domain, int type, int protocol)
{
        int fd, host_fd;

        if ((fd = alloc_fd()) < 0)
                return fd;
        
        host_fd = dsys_socket(domain, type, protocol);
        if (host_fd < 0) {
                free_fd(fd);
                fd = host_fd;
        } else {
                fd_dic[fd]->type = FD_TYPE_SC_HOST_FILE;
                fd_dic[fd]->host_fd = host_fd;
                fd_dic[fd]->sc_file_type = SC_FILE_TYPE_NET;
                fd_dsys_stat(fd);
        }

        return fd;
}

long sc_sys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
        fd_filter(sockfd);

        return dsys_bind(fd_dic[sockfd]->host_fd, addr, addrlen);
}

long sc_sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
        struct sockaddr_in *addr_in = (void *)addr;
        
        fd_filter(sockfd);

        if (ntohs(addr_in->sin_port) == 8080) {
                fd_dic[sockfd]->sc_file_type = SC_FILE_TYPE_NET_NOENC;
        }

        return dsys_connect(fd_dic[sockfd]->host_fd, addr, addrlen);
}

long sc_sys_recvfrom(int sockfd, void *buf, size_t len, int flags,
                            struct sockaddr *src_addr, socklen_t *addrlen)
{
        int ret;
        
        fd_filter(sockfd);

        ret = dsys_recvfrom(fd_dic[sockfd]->host_fd, buf, len, flags, src_addr, addrlen);
        if (ret > 0) {
                fd_mock_enc_hash(sockfd, ret, 0);
                a_fetch_add(&io_cnt_net, ret);
        }

        return ret;
}

long sc_sys_sendto(int sockfd, const void *buf, size_t len, int flags,
                          const struct sockaddr *dest_addr, socklen_t addrlen)
{
        int ret;
        
        fd_filter(sockfd);

        ret = dsys_sendto(fd_dic[sockfd]->host_fd, buf, len, flags, dest_addr, addrlen);
        if (ret > 0) {
                fd_mock_enc_hash(sockfd, ret, 1);
                a_fetch_add(&io_cnt_net, ret);
        }

        return ret;
}

long sc_sys_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
        fd_filter(sockfd);

        return dsys_getsockname(fd_dic[sockfd]->host_fd, addr, addrlen);
}

long sc_sys_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
        fd_filter(sockfd);

        return dsys_getpeername(fd_dic[sockfd]->host_fd, addr, addrlen);
}

long sc_sys_getsockopt(int sockfd, int level, int optname,
                              void *optval, socklen_t *optlen)
{
        fd_filter(sockfd);

        return dsys_getsockopt(fd_dic[sockfd]->host_fd, level, optname, optval, optlen);
}

long sc_sys_setsockopt(int sockfd, int level, int optname,
                              const void *optval, socklen_t optlen)
{
        fd_filter(sockfd);

        return dsys_setsockopt(fd_dic[sockfd]->host_fd, level, optname, optval, optlen);
}

static int fd_set_to_host(int nfds, fd_set *fds, fd_set *__fds)
{
        int fd;
        int __nfds = 0;

        FD_ZERO(__fds);

        for (fd = 3; fd < nfds; fd++) {
                if (FD_ISSET(fd, fds)) {
                        BUG_ON(fd_dic[fd]->type != FD_TYPE_SC_HOST_FILE);
                        FD_SET(fd_dic[fd]->host_fd, __fds);
                        __nfds = fd_dic[fd]->host_fd >= __nfds ? fd_dic[fd]->host_fd + 1 : __nfds;
                }
        }

        return __nfds;
}

static void fd_set_to_guest(int nfds, fd_set *fds, fd_set *__fds)
{
        int fd;

        FD_ZERO(fds);

        for (fd = 3; fd < nfds; fd++) {
                if (fd_dic[fd]->type != FD_TYPE_SC_HOST_FILE) {
                        continue;
                }
                if (FD_ISSET(fd_dic[fd]->host_fd, __fds)) {
                        FD_SET(fd, fds);
                }
        }
}

long sc_sys_select(int nfds, fd_set *readfds, fd_set *writefds,
                   fd_set *exceptfds, struct timeval *timeout)
{
        int __nfds, __nfds1, __nfds2, ret;
        fd_set __readfds;
        fd_set __writefds;

        BUG_ON(!readfds || !writefds || exceptfds);

        __nfds1 = fd_set_to_host(nfds, readfds, &__readfds);
        __nfds2 = fd_set_to_host(nfds, writefds, &__writefds);
        __nfds = __nfds1 > __nfds2 ? __nfds1 : __nfds2;

        ret = dsys_select(__nfds, &__readfds, &__writefds, NULL, NULL);

        fd_set_to_guest(nfds, readfds, &__readfds);
        fd_set_to_guest(nfds, writefds, &__writefds);
        
        return ret;
}

long sc_sys_shutdown(int sockfd, int how)
{
        fd_filter(sockfd);

        return dsys_shutdown(fd_dic[sockfd]->host_fd, how);
}

#define POLL_MAX_NFDS  16
long sc_sys_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
        int i, ret;
        struct pollfd __fds[POLL_MAX_NFDS];

        BUG_ON(nfds > POLL_MAX_NFDS);

        for (i = 0; i < nfds; i++) {
                __fds[i] = fds[i];
                BUG_ON(fd_dic[fds[i].fd]->type != FD_TYPE_SC_HOST_FILE);
                __fds[i].fd = fd_dic[fds[i].fd]->host_fd;
        }

        a_fetch_add(&dsys_cnt_net, 1);
        ret = dsys_poll(__fds, nfds, timeout);

        for (i = 0; i < nfds; i++) {
                fds[i].revents = __fds[i].revents;
        }

        return ret;
}

long sc_sys_lstat(const char *pathname, struct stat *statbuf)
{
        path_rewrite(pathname);
        if (!path_on_host(pathname)) {
                return __xstatxx(FS_REQ_FSTATAT,
                                 AT_FDCWD, /* dirfd */
                                 pathname, /* path  */
                                 AT_SYMLINK_NOFOLLOW, /* flags */
                                 statbuf, /* statbuf */
                                 sizeof(struct stat));
        }

        if (is_libtmpfs_path(pathname)) {
                return libtmpfs_fstatat(-101, pathname, statbuf, AT_SYMLINK_NOFOLLOW);
        }

        path_dsys_stat(pathname);
        return dsys_lstat(pathname, statbuf);
}

long sc_sys_dup(int oldfd)
{
        int newfd, newhostfd;
        
        fd_filter(oldfd);

        BUG_ON(is_libtmpfs_fd(oldfd));

        newhostfd = dsys_dup(fd_dic[oldfd]->host_fd);
        BUG_ON(newhostfd < 0);

        newfd = alloc_fd();
        BUG_ON(newfd < 0);

        memcpy(fd_dic[newfd], fd_dic[oldfd], sizeof(*fd_dic[oldfd]));
        fd_dic[newfd]->host_fd = newhostfd;

        return newfd;
}

long sc_sys_chmod(const char *pathname, mode_t mode)
{
        path_rewrite(pathname);
        if (!path_on_host(pathname)) {
                return 0;
        }

        BUG_ON(is_libtmpfs_path(pathname));

        path_dsys_stat(pathname);
        return dsys_chmod(pathname, mode);
}

long sc_sys_print_stat(const char *s)
{
        // printf("dsys_cnt_lib %d\n", dsys_cnt_lib);
        // printf("dsys_cnt_tmp %d\n", dsys_cnt_tmp);
        // printf("dsys_cnt_net %d\n", dsys_cnt_net);
        // printf("dsys_cnt_all %d\n", dsys_cnt_all);
        // printf("io_cnt_lib %d\n", io_cnt_lib);
        // printf("io_cnt_tmp %d\n", io_cnt_tmp);
        // printf("io_cnt_net %d\n", io_cnt_net);
        printf("stat\n");
        printf("t_delegate,%s %lu\n", s, t_delegate);
        printf("t_attest,%s %lu\n", s, t_attest);
        printf("t_encrypt,%s %lu\n", s, t_encrypt);
        printf("t_redirect,%s %lu\n", s, t_redirect);
        // printf("t_pgfault,%s %lu\n", s, t_pgfault);
        usys_split_container(SYS_SC_OP_PRINT_STAT, (long)s, 0, 0, 0);
        return 0;
}

#define STAT_T_ATTEST   0x3
#define STAT_T_ENCRYPT  0x4
long sc_sys_get_stat(int stat)
{
        switch (stat) {
        case STAT_T_ATTEST:
                return t_attest;
        case STAT_T_ENCRYPT:
                return t_encrypt;
        default:
                return usys_split_container(SYS_SC_OP_GET_STAT, stat, 0, 0, 0);
        }
}

long sc_sys_defer_encrypt(int defer)
{
        if (defer && !use_defer_encrypt) {
                defer_encrypt_cnt = 0;
                use_defer_encrypt = 1;
        } else if (!defer && use_defer_encrypt) {
                use_defer_encrypt = 0;
                t_encrypt += mock_encryption(defer_encrypt_cnt, 1, 1);
        }

        return 0;
}

long sc_sys_start_polling(void)
{
        use_polling = 1;

        usys_split_container(SYS_SC_OP_START_POLLING, 0, 0, 0, 0);

        return 0;
}

long sc_sys_wait_finish(void)
{
        return usys_split_container(SYS_SC_OP_WAIT_FINISH, 0, 0, 0, 0);
}

long sc_sys_symlink(const char *target, const char *linkpath)
{
        path_rewrite(linkpath);
        if (!path_on_host(linkpath)) {
                return chcore_symlinkat(target, AT_FDCWD, linkpath);
        }

        BUG_ON(is_libtmpfs_path(linkpath));

        path_dsys_stat(linkpath);
        BUG_ON(1);
        return 0;
}

long sc_sys_snapshot(void)
{
        int fd, ret;
        struct timespec tp;

        for (;;) {
                ret = usys_split_container(SYS_SC_OP_SNAPSHOT, 1, 0, 0, 0);
                if (ret == -EAGAIN) {
                        usys_yield();
                } else {
                        BUG_ON(ret);
                        break;
                }
        }

        for (fd = 0; fd < 3; fd++) {
                BUG_ON(!fd_dic[fd] ||
                       fd_dic[fd]->type != FD_TYPE_SC_HOST_FILE ||
                       fd_dic[fd]->sc_file_type != SC_FILE_TYPE_STDIO ||
                       fd_dic[fd]->host_fd != fd);
        }
        for (fd = 3; fd < MAX_FD; fd++) {
                if (!fd_dic[fd] ||
                    fd_dic[fd]->type == FD_TYPE_PIPE ||
                    fd_dic[fd]->type == FD_TYPE_EVENT ||
                    fd_dic[fd]->type == FD_TYPE_EPOLL) {
                        continue;
                }
                if (fd_dic[fd]->type == FD_TYPE_SC_HOST_FILE &&
                    fd_dic[fd]->sc_file_type == SC_FILE_TYPE_EPOLL &&
                    fd_dic[fd]->host_fd == -1) {
                        continue;
                }
                usys_putstr(fd, 0);
                usys_putstr(fd_dic[fd]->type, 0);
                usys_putstr(fd_dic[fd]->sc_file_type, 0);
                BUG_ON(1);
        }

        usys_split_container(SYS_SC_OP_SNAPSHOT, 0, 0, 0, 0);

        dsys_cnt_lib = 0;
        dsys_cnt_tmp = 0;
        dsys_cnt_net = 0;
        dsys_cnt_all = 0;
        io_cnt_lib = 0;
        io_cnt_tmp = 0;
        io_cnt_net = 0;
        t_delegate = 0;
        t_attest = 0;
        t_encrypt = 0;
        t_pgfault = 0;
        t_redirect = 0;

        usys_split_container(SYS_SC_OP_REG_T_PGFAULT, (unsigned long)&t_pgfault, 0, 0, 0);

        dsys_clock_gettime(CLOCK_REALTIME, &tp);
        base_real_time_ns = tp.tv_sec * 1000000000UL + tp.tv_nsec;

        base_mono_time_ns = pmu_read_real_cycle();

#ifndef CHCORE_SPLIT_CONTAINER_SYNC
        use_sync = usys_split_container(SYS_SC_OP_SYNC_IS_ENABLED, 0, 0, 0, 0);

        if (!use_sync) {
                usys_split_container(SYS_SC_OP_SIGNAL_ALL_NOTIFCS, 0, 0, 0, 0);
        }
#endif /* CHCORE_SPLIT_CONTAINER_SYNC */

        return 0;
}

long sc_sys_dup3(int oldfd, int newfd, int flags)
{
        int ret;

        BUG_ON(!fd_dic[oldfd] || fd_dic[oldfd]->type != FD_TYPE_SC_HOST_FILE);
        BUG_ON(!fd_dic[newfd] || fd_dic[newfd]->type != FD_TYPE_SC_HOST_FILE);
        
        BUG_ON(is_libtmpfs_fd(oldfd));

        fd_dsys_stat(oldfd);

        ret = dsys_dup3(fd_dic[oldfd]->host_fd, fd_dic[newfd]->host_fd, flags);
        if (ret >= 0)
                fd_dic[newfd]->sc_file_type = fd_dic[oldfd]->sc_file_type;

        return newfd;
}

long sc_sys_statx(int dirfd, const char *pathname, int flags,
                  unsigned int mask, struct statx *statxbuf)
{
        if (dirfd == AT_FDCWD) {
                path_rewrite(pathname);
                BUG_ON(!path_on_host(pathname));
                if (is_libtmpfs_path(pathname)) {
                        return -ENOSYS;
                }
                path_dsys_stat(pathname);
                return dsys_statx(dirfd, pathname, flags, mask, statxbuf);
        } else {
                fd_filter(dirfd);
                BUG_ON(is_libtmpfs_fd(dirfd));
                return dsys_statx(fd_dic[dirfd]->host_fd, pathname, flags, mask, statxbuf);
        }
}

long sc_sys_clock_getres(clockid_t clk_id, struct timespec *tp)
{
        tp->tv_sec = 0;
        tp->tv_nsec = 1;

        return 0;
}

long sc_sys_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
        unsigned long mono_time_ns, real_time_ns;

        mono_time_ns = pmu_read_real_cycle();

        real_time_ns = base_real_time_ns + (mono_time_ns - base_mono_time_ns);
        tp->tv_sec = real_time_ns / 1000000000UL;
        tp->tv_nsec = real_time_ns % 1000000000UL;

        return 0;
}

long sc_sys_pread(int fd, void *buf, size_t count, off_t offset)
{
        int ret;
        
        fd_filter(fd);
        
        BUG_ON(is_libtmpfs_fd(fd));

        ret = dsys_pread(fd_dic[fd]->host_fd, buf, count, offset);
        if (ret > 0) {
                fd_mock_enc_hash(fd, ret, 0);
                fd_io_stat(fd, ret);
        }

        return ret;
}

long sc_sys_access(const char *pathname, int mode)
{
        path_rewrite(pathname);
        if (!path_on_host(pathname)) {
                return -EDONTHOOK;
        }

        BUG_ON(is_libtmpfs_path(pathname));

        path_dsys_stat(pathname);
        return dsys_access(pathname, mode);
}

void sc_init(void)
{
        int fd;
        struct timespec tp;
        
        is_enclave = usys_split_container(SYS_SC_OP_IS_ENCLAVE, 0, 0, 0, 0);
        if (!is_enclave) {
                return;
        }

        // usys_putstr(use_libtmpfs, 0);

        usys_split_container(SYS_SC_OP_REG_T_PGFAULT, (unsigned long)&t_pgfault, 0, 0, 0);

        for (fd = 0; fd < 3; fd++) {
                fd_dic[fd]->type = FD_TYPE_SC_HOST_FILE;
                fd_dic[fd]->host_fd = fd;
                fd_dic[fd]->sc_file_type = SC_FILE_TYPE_STDIO;
        }

        dsys_clock_gettime(CLOCK_REALTIME, &tp);
        base_real_time_ns = tp.tv_sec * 1000000000UL + tp.tv_nsec;

        base_mono_time_ns = pmu_read_real_cycle();

        if (use_libtmpfs) {
                libtmpfs_init();
                libtmpfs_mkdir("/tmp", 0777);
        }

#ifndef CHCORE_SPLIT_CONTAINER_SYNC
        use_sync = usys_split_container(SYS_SC_OP_SYNC_IS_ENABLED, 0, 0, 0, 0);
#endif /* CHCORE_SPLIT_CONTAINER_SYNC */
}

#define SYS_sc_snapshot         0x1000
#define SYS_sc_print_stat       0x1001
#define SYS_sc_start_polling    0x1002
#define SYS_sc_defer_encrypt    0x1003
#define SYS_sc_get_stat         0x1004
#define SYS_sc_wait_finish      0x1005

int __sc_syscall_hook(long n,
                      long a, long b, long c, long d, long e, long f,
                      long *ret)
{
        if (!is_enclave) {
                return -1;
        }

        *ret = -EDONTHOOK;

        switch (n) {
        case SYS_open:
                *ret = sc_sys_open((void *)a, b, c);
                break;
        case SYS_ioctl:
                *ret = sc_sys_ioctl(a, b, (void *)c);
                break;
        case SYS_writev:
                *ret = sc_sys_writev(a, (void *)b, c);
                break;
        case SYS_read:
                *ret = sc_sys_read(a, (void *)b, c);
                break;
        case SYS_mmap:
                *ret = sc_sys_mmap((void *)a, b, c, d, e, f);
                break;
        case SYS_close:
                *ret = sc_sys_close(a);
                break;
        case SYS_fcntl:
                if (b == F_DUPFD || b == F_DUPFD_CLOEXEC)
                        *ret = sc_sys_dup(a);
                else
                        *ret = sc_sys_fcntl(a, b, c);
                break;
        case SYS_fstat:
                *ret = sc_sys_fstat(a, (void *)b);
                break;
        case SYS_readlink:
                *ret = sc_sys_readlink((void *)a, (void *)b, c);
                break;
        case SYS_stat:
                *ret = sc_sys_stat((void *)a, (void *)b);
                break;
        case SYS_getdents64:
                *ret = sc_sys_getdents64(a, (void *)b, c);
                break;
        case SYS_write:
                *ret = sc_sys_write(a, (void *)b, c);
                break;
        case SYS_lseek:
                *ret = sc_sys_lseek(a, b, c);
                break;
        case SYS_rename:
                *ret = sc_sys_rename((void *)a, (void *)b);
                break;
        case SYS_getuid:
                *ret = dsys_getuid();
                break;
        case SYS_geteuid:
                *ret = dsys_geteuid();
                break;
        case SYS_getgid:
                *ret = dsys_getgid();
                break;
        case SYS_getegid:
                *ret = dsys_getegid();
                break;
        case SYS_setuid:
                *ret = dsys_setuid(a);
                break;
        case SYS_setgid:
                *ret = dsys_setgid(a);
                break;
        case SYS_mkdir:
                *ret = sc_sys_mkdir((void *)a, b);
                break;
        case SYS_readv:
                *ret = sc_sys_readv(a, (void *)b, c);
                break;
        case SYS_epoll_create1:
                *ret = sc_sys_epoll_create1(a);
                break;
        case SYS_socket:
                *ret = sc_sys_socket(a, b, c);
                break;
        case SYS_bind:
                *ret = sc_sys_bind(a, (void *)b, c);
                break;
        case SYS_connect:
                *ret = sc_sys_connect(a, (void *)b, c);
                break;
        case SYS_recvfrom:
                *ret = sc_sys_recvfrom(a, (void *)b, c, d, (void *)e, (void *)f);
                break;
        case SYS_sendto:
                *ret = sc_sys_sendto(a, (void *)b, c, d, (void *)e, f);
                break;
        case SYS_getcwd:
                *ret = dsys_getcwd((void *)a, b);
                break;
        case SYS_sched_getaffinity:
                *ret = dsys_sched_getaffinity(a, b, (void *)c);
                break;
        case SYS_mbind:
                *ret = -ENOSYS;
                break;
        case SYS_get_mempolicy:
                *ret = -ENOSYS;
                break;
        case SYS_getpid:
                *ret = dsys_getpid();
                break;
        case SYS_setsockopt:
                *ret = sc_sys_setsockopt(a, b, c, (void *)d, e);
                break;
        case SYS_getsockopt:
                *ret = sc_sys_getsockopt(a, b, c, (void *)d, (void *)e);
                break;
        case SYS_getsockname:
                *ret = sc_sys_getsockname(a, (void *)b, (void *)c);
                break;
        case SYS_getpeername:
                *ret = sc_sys_getpeername(a, (void *)b, (void *)c);
                break;
        case SYS_poll:
                *ret = sc_sys_poll((void *)a, b, c);
                break;
        case SYS_clock_gettime:
                *ret = sc_sys_clock_gettime(a, (void *)b);
                break;
        case SYS_clock_getres:
                *ret = sc_sys_clock_getres(a, (void *)b);
                break;
        case SYS_lstat:
                *ret = sc_sys_lstat((void *)a, (void *)b);
                break;
        case SYS_dup:
                *ret = sc_sys_dup(a);
                break;
        case SYS_sendfile:
                *ret = -ENOSYS;
                break;
        case SYS_chmod:
                *ret = sc_sys_chmod((void *)a, b);
                break;
        case SYS_symlink:
                *ret = sc_sys_symlink((void *)a, (void *)b);
                break;
        case SYS_sc_snapshot:
                *ret = sc_sys_snapshot();
                break;
        case SYS_eventfd2:
                *ret = -EDONTHOOK;
                break;
        case SYS_epoll_ctl:
                *ret = sc_sys_epoll_ctl(a, b, c, (void *)d);
                break;
        case SYS_epoll_pwait:
                *ret = sc_sys_epoll_pwait(a, (void *)b, c, d, (void *)e);
                break;
        case SYS_pipe2:
                *ret = -EDONTHOOK;
                break;
        case SYS_capget:
                *ret = dsys_capget((void *)a, (void *)b);
                break;
        case SYS_dup3:
                *ret = sc_sys_dup3(a, b, c);
                break;
        case SYS_statx:
                *ret = sc_sys_statx(a, (void *)b, c, d, (void *)e);
                break;
        case SYS_pread:
                *ret = sc_sys_pread(a, (void *)b, c, d);
                break;
        case SYS_shutdown:
                *ret = sc_sys_shutdown(a, b);
                break;
        case SYS_access:
                *ret = sc_sys_access((void *)a, b);
                break;
        case SYS_sched_getattr:
                *ret = dsys_sched_getattr(a, (void *)b, c, d);
                break;
        case SYS_umask:
                *ret = dsys_umask(a);
                break;
        case SYS_sc_print_stat:
                *ret = sc_sys_print_stat((void *)a);
                break;
        case SYS_sc_get_stat:
                *ret = sc_sys_get_stat(a);
                break;
        case SYS_sc_defer_encrypt:
                *ret = sc_sys_defer_encrypt(a);
                break;
        case SYS_sc_start_polling:
                *ret = sc_sys_start_polling();
                break;
        case SYS_sc_wait_finish:
                *ret = sc_sys_wait_finish();
                break;
        case SYS_select:
                *ret = sc_sys_select(a, (void *)b, (void *)c, (void *)d, (void *)e);
                break;
        // case SYS_futex:
        //         *ret = dfutex((void *)a, b, c, (void *)d, (void *)e, f);
        //         break;
        case SYS_ftruncate:
        case SYS_unlink:
        case SYS_sysinfo:
        case SYS_listen:
        case SYS_accept4:
        case SYS_setitimer:
        case SYS_times:
        case SYS_getgroups:
        case SYS_setgroups:
        case SYS_dup2:
        case SYS_sched_setattr:
        case SYS_sched_setaffinity:
        case SYS_rt_sigtimedwait:
                usys_putstr(n, 0);
                while (1);
                break;
        default:
                break;
        }

        return *ret == -EDONTHOOK ? -1 : 0;
}

#ifndef CHCORE_SPLIT_CONTAINER_SYNC
static void set_notifc_sem(cap_t notifc_cap)
{
        sem_t *sem;

        sem = dsem_init(0, 0);
        BUG_ON(!sem);

        usys_split_container(SYS_SC_OP_SET_SEM, notifc_cap, (long)sem, 0, 0);
}

cap_t sc_create_notifc(void)
{
        cap_t notifc_cap;

        notifc_cap = chcore_syscall0(CHCORE_SYS_create_notifc);

        if (!is_enclave || use_sync) {
                return notifc_cap;
        }

        BUG_ON(notifc_cap < 0);

        set_notifc_sem(notifc_cap);

        return notifc_cap;
}

int sc_wait(cap_t notifc_cap, bool is_block, struct timespec *timeout)
{
        sem_t *sem;
        struct timespec abs_timeout;
        
        if (!is_enclave || use_sync) {
                chcore_syscall3(CHCORE_SYS_wait, notifc_cap, is_block, (long)timeout);
                if (is_enclave && !use_sync) {
                        goto sc_wait_retry;
                }
                return 0;
        }

sc_wait_retry:
        sem = (void *)usys_split_container(SYS_SC_OP_GET_SEM, notifc_cap, 0, 0, 0);
        if (!sem) {
                set_notifc_sem(notifc_cap);
                goto sc_wait_retry;
        } else if ((long)sem == -ECAPBILITY) {
                return -ECAPBILITY;
        }

        if (!is_block) {
                return dsem_trywait(sem);
        } else if (timeout) {
                sc_sys_clock_gettime(CLOCK_REALTIME, &abs_timeout);
                abs_timeout.tv_sec += timeout->tv_sec;
                abs_timeout.tv_nsec += timeout->tv_nsec;
                abs_timeout.tv_sec += abs_timeout.tv_nsec / 1000000000UL;
                abs_timeout.tv_nsec %= 1000000000UL;
                while (dsem_timedwait(sem, &abs_timeout));
                return 0;
        } else {
                while (dsem_wait(sem));
                return 0;
        }
}

int sc_notify(cap_t notifc_cap)
{
        sem_t *sem;
        
        if (!is_enclave || use_sync) {
                int ret;

                do {
                        ret = chcore_syscall1(CHCORE_SYS_notify, notifc_cap);

                        if (ret == -EAGAIN) {
                                // printf("%s retry\n", __func__);
                                usys_yield();
                        }
                } while (ret == -EAGAIN);

                return ret;
        }

sc_notify_retry:
        sem = (void *)usys_split_container(SYS_SC_OP_GET_SEM, notifc_cap, 1, 0, 0);
        if (!sem) {
                set_notifc_sem(notifc_cap);
                goto sc_notify_retry;
        } else if ((long)sem == -ECAPBILITY) {
                return -ECAPBILITY;
        }

        return dsem_post(sem);
}
#endif /* CHCORE_SPLIT_CONTAINER_SYNC */

#endif /* CHCORE_SPLIT_CONTAINER */

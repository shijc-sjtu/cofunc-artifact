#pragma once

#include <chcore/type.h>

void sc_init(void);

int __sc_syscall_hook(long n,
                        long a, long b, long c, long d, long e, long f,
                        long *ret);

#ifndef CHCORE_SPLIT_CONTAINER_SYNC
cap_t sc_create_notifc(void);
int sc_wait(cap_t notifc_cap, bool is_block, struct timespec *timeout);
int sc_notify(cap_t notifc_cap);
#endif /* CHCORE_SPLIT_CONTAINER_SYNC */

#define sc_syscall0_hook do {                                         \
        long ret;                                                       \
        if (!__sc_syscall_hook(n, 0, 0, 0, 0, 0, 0, &ret)) {          \
                return ret;                                             \
        }                                                               \
} while (0)

#define sc_syscall1_hook do {                                         \
        long ret;                                                       \
        if (!__sc_syscall_hook(n, a, 0, 0, 0, 0, 0, &ret)) {          \
                return ret;                                             \
        }                                                               \
} while (0)

#define sc_syscall2_hook do {                                         \
        long ret;                                                       \
        if (!__sc_syscall_hook(n, a, b, 0, 0, 0, 0, &ret)) {          \
                return ret;                                             \
        }                                                               \
} while (0)

#define sc_syscall3_hook do {                                         \
        long ret;                                                       \
        if (!__sc_syscall_hook(n, a, b, c, 0, 0, 0, &ret)) {          \
                return ret;                                             \
        }                                                               \
} while (0)

#define sc_syscall4_hook do {                                         \
        long ret;                                                       \
        if (!__sc_syscall_hook(n, a, b, c, d, 0, 0, &ret)) {          \
                return ret;                                             \
        }                                                               \
} while (0)

#define sc_syscall5_hook do {                                         \
        long ret;                                                       \
        if (!__sc_syscall_hook(n, a, b, c, d, e, 0, &ret)) {          \
                return ret;                                             \
        }                                                               \
} while (0)

#define sc_syscall6_hook do {                                         \
        long ret;                                                       \
        if (!__sc_syscall_hook(n, a, b, c, d, e, f, &ret)) {          \
                return ret;                                             \
        }                                                               \
} while (0)

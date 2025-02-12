#ifdef CHCORE_SPLIT_CONTAINER
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <debug_lock.h>
#include <syscall_arch.h>
#include <futex.h>
#include <memory.h>
#include <chcore/defs.h>
#include <chcore/bug.h>
#include <chcore/syscall.h>
#include <chcore/sc_shm.h>
#include "pthread_impl.h"

/*
 * ATTENTION: printf uses futex, so disable futex in __lockfile before using
 *	      printf in futex.
 */
#define chcore_futex_debug 0
#define printf_futex(fmt, ...)                 \
        do {                                   \
                if (chcore_futex_debug)        \
                        printf("%s:%d " fmt,   \
                               __FILE__,       \
                               __LINE__,       \
                               ##__VA_ARGS__); \
        } while (0)

/*
 * TODO: 1. Store waiting events in hash table.
 *       2. Fine-grained lock (e.g., per uaddr).
 *       3. A more proper replacement of sys_notify may be needed.
 *          Because sys_notify will wakeup following sys_wait,
 *          which is a little bit unsuitable for futex.
 */

/*
 * XXX: Requeue from one addr to another addr.
 *	Still use the old notifc_cap.
 */
struct requeued_futex {
        sem_t *sem;
        struct requeued_futex *next;
};

struct futex_entry {
        sem_t *sem;
        int *uaddr;
        /* waiter_count does not include requeued ones */
        int waiter_count;
        struct notifc_cache_entry *notifc_cache_entry;

        struct requeued_futex *requeued_futex_list;
};
#define MAX_FUTEX_ENTRIES 256
static struct futex_entry futex_entries[MAX_FUTEX_ENTRIES] = {0};

/* XXX: Reuse notification created but never free */
struct notifc_cache_entry {
        sem_t *sem;
        struct notifc_cache_entry *next;
};
static struct notifc_cache_entry *notifc_cache = NULL;

/*
 * XXX: Every futex op will lock to protect notification cache
 *      and futex_entries.
 */
static int volatile futex_lock = 0;

#define FUTEX_CMD_MASK ~(FUTEX_PRIVATE | FUTEX_CLOCK_REALTIME)

sem_t *dsem_init(int pshared, unsigned value);
int dsem_wait(sem_t *sem);
int dsem_timedwait(sem_t *sem, const struct timespec *timeout);
int dsem_post(sem_t *sem);

static bool futex_has_waiter(struct futex_entry *entry)
{
        return entry->waiter_count > 0 || entry->requeued_futex_list != NULL;
}

/* Find notifc_cap from cache, or create a new one */
static struct notifc_cache_entry *futex_alloc_notifc(void)
{
        struct notifc_cache_entry *cur_notifc_cache;
        sem_t *sem;

        if (notifc_cache != NULL) {
                cur_notifc_cache = notifc_cache;
                notifc_cache = notifc_cache->next;
        } else {
                sem = dsem_init(0, 0);
                if (sem == NULL)
                        BUG("create notifc failed");
                cur_notifc_cache = malloc(sizeof(*cur_notifc_cache));
                if (!cur_notifc_cache)
                        BUG("alloc notifc cache failed");
                cur_notifc_cache->sem = sem;
                cur_notifc_cache->next = NULL;
        }

        return cur_notifc_cache;
}

static int dfutex_wait(int *uaddr, int futex_op, int val,
                           struct timespec *timeout)
{
        sem_t *sem = NULL;
        int empty_idx = -1, idx = -1;
        int i, ret;
        struct notifc_cache_entry *cur_notifc_cache;

        chcore_spin_lock(&futex_lock);

        /* check if uaddr contains expected value */
        if (*uaddr != val) {
                chcore_spin_unlock(&futex_lock);
                return -EAGAIN;
        }

        /*
         * Find if already waited on the same uaddr. If not found,
         * find a empty entry to put current wait request.
         */
        for (i = 0; i < MAX_FUTEX_ENTRIES; i++) {
                if (futex_has_waiter(&futex_entries[i])
                    && futex_entries[i].uaddr == uaddr) {
                        idx = i;
                        break;
                } else if (!futex_has_waiter(&futex_entries[i])) {
                        empty_idx = i;
                }
        }

        if (empty_idx < 0 && idx < 0)
                BUG("futex entries overflow");

        if (idx >= 0) {
                /*
                 * 1. waiter_count > 0: already waited on the same uaddr
                 * 2. waiter_count = 0: have requeued waiters
                 */
                sem = futex_entries[idx].sem;
                futex_entries[idx].waiter_count++;
        } else {
                /* First one to wait on the uaddr */
                cur_notifc_cache = futex_alloc_notifc();
                BUG_ON(!cur_notifc_cache);
                sem = cur_notifc_cache->sem;

                idx = empty_idx;
                futex_entries[idx] = (struct futex_entry){
                        .sem = sem,
                        .uaddr = uaddr,
                        .waiter_count = 1,
                        .notifc_cache_entry = cur_notifc_cache,
                        .requeued_futex_list = NULL};
        }
        printf_futex(
                "futex wait:%d addr:%p sem:%p\n", idx, uaddr, sem);
        chcore_spin_unlock(&futex_lock);

        /* Try to wait */
        if (timeout) {
                dsem_timedwait(sem, timeout);
        } else {
                dsem_wait(sem);
        }

        assert((ret == 0) || (ret == -ETIMEDOUT));

        /* After wake up */
        chcore_spin_lock(&futex_lock);
        futex_entries[idx].waiter_count--;
        /*
         * If this is the last waiter: not close the notification
         * but put it in cache in case of following wait.
         */
        if (!futex_has_waiter(&futex_entries[idx])) {
                cur_notifc_cache = futex_entries[idx].notifc_cache_entry;
                cur_notifc_cache->next = notifc_cache;
                notifc_cache = cur_notifc_cache;
        }
        chcore_spin_unlock(&futex_lock);

        return 0;
}
/*
 * FIXME: The wake up sequence for requeued request is wrong.
 *	  Requeued waiters are always awoken after waiters which wait on the
 *	  address at beginning. Although this does not affect the
 *        correctness of futex wake.
 */
static int dfutex_wake(int *uaddr, int futex_op, int val)
{
        sem_t *sem;
        int send_count = 0, idx = -1;
        int i, ret;
        struct requeued_futex *requeued;

        chcore_spin_lock(&futex_lock);
        printf_futex("futex wake uaddr:%p val:%d\n", uaddr, val);
        /* Find waiters with the same uaddr */
        for (i = 0; i < MAX_FUTEX_ENTRIES; i++) {
                if (futex_has_waiter(&futex_entries[i])
                    && futex_entries[i].uaddr == uaddr) {
                        idx = i;
                        break;
                }
        }

        if (idx == -1) {
                printf_futex("futex wake not found\n");
                send_count = 0;
                goto out_unlock;
        }

        printf_futex("futex wake:%d\n", idx);
        /* 1. send to waiters which wait at beginning */
        sem = futex_entries[idx].sem;
        send_count = futex_entries[idx].waiter_count;
        send_count = send_count < val ? send_count : val;
        /*
         * TODO: provide a parameter for notify syscall to notify multiple
         *	 waiters within one syscall.
         */
        for (i = 0; i < send_count; i++) {
                printf_futex("\twake origin sem:%d\n", sem);
                ret = dsem_post(sem);
                BUG_ON(ret != 0);
        }

        /* 2. send to requeued waiters */
        requeued = futex_entries[idx].requeued_futex_list;
        printf_futex(
                "futex wake send_count:%d queue:%p\n", send_count, requeued);
        while (send_count < val && requeued) {
                printf_futex("\twake queue sem:%p\n", requeued->sem);
                ret = dsem_post(requeued->sem);
                BUG_ON(ret != 0);
                futex_entries[idx].requeued_futex_list = requeued->next;
                free(requeued);
                requeued = futex_entries[idx].requeued_futex_list;
        }

out_unlock:
        chcore_spin_unlock(&futex_lock);

        return send_count;
}

/*
 * TODO: Currently only support requeue one waiter.
 */
static int dfutex_requeue(int *uaddr, int *uaddr2, int nr_wake, int nr_requeue)
{
        BUG_ON(nr_wake != 0);
        BUG_ON(nr_requeue != 1);
        int empty_idx = -1, send_count = 0, idx = -1, idx2 = -1;
        int i, ret;
        struct requeued_futex *requeue_iter, *requeue;
        struct notifc_cache_entry *cur_notifc_cache;

        if (uaddr == uaddr2)
                return -EINVAL;

        chcore_spin_lock(&futex_lock);
        for (i = 0; i < MAX_FUTEX_ENTRIES; i++) {
                if (futex_has_waiter(&futex_entries[i])
                    && futex_entries[i].uaddr == uaddr) {
                        idx = i;
                } else if (futex_has_waiter(&futex_entries[i])
                           && futex_entries[i].uaddr == uaddr2) {
                        idx2 = i;
                } else if (!futex_has_waiter(&futex_entries[i])) {
                        empty_idx = i;
                }

                if (idx != -1 && idx2 != -1)
                        break;
        }

        if (idx == -1) {
                printf_futex("futex requeue not found\n");
                chcore_spin_unlock(&futex_lock);
                return -EINVAL;
        }

        if (idx2 == -1 && empty_idx == -1)
                BUG("futex entries overflow");

        /* requeue target does not contain any waiter */
        if (idx2 == -1) {
                idx2 = empty_idx;
                cur_notifc_cache = futex_alloc_notifc();
                BUG_ON(!cur_notifc_cache);

                futex_entries[idx2] = (struct futex_entry){
                        .sem = cur_notifc_cache->sem,
                        .uaddr = uaddr2,
                        .waiter_count = 0,
                        .notifc_cache_entry = cur_notifc_cache,
                        .requeued_futex_list = NULL};
        }

        if (idx2 == -1 && empty_idx == -1)
                BUG("futex entries overflow");

        if (futex_entries[idx].waiter_count != 0) {
                /* requeue a waiter that wait on the address at beginning */
                requeue = malloc(sizeof(*requeue));
                if (!requeue)
                        BUG("out of memory");
                requeue->next = NULL;
                requeue->sem = futex_entries[idx].sem;
        } else {
                /* requeue a waiter that is requeued previously */
                requeue = futex_entries[idx].requeued_futex_list;
                futex_entries[idx].requeued_futex_list =
                        futex_entries[idx].requeued_futex_list->next;
                requeue->next = NULL;
        }

        /* add to the tail of requeued list */
        requeue_iter = futex_entries[idx2].requeued_futex_list;
        printf_futex("futex requeue old:%d addr:%p sem:%p new:%d addr:%p\n",
                     idx,
                     uaddr,
                     requeue->sem,
                     idx2,
                     uaddr2);
        if (!requeue_iter) {
                futex_entries[idx2].requeued_futex_list = requeue;
        } else {
                while (requeue_iter->next)
                        requeue_iter = requeue_iter->next;
                requeue_iter->next = requeue;
        }

        chcore_spin_unlock(&futex_lock);
        return 0;
}

int dfutex(int *uaddr, int futex_op, int val, struct timespec *timeout,
               int *uaddr2, int val3)
{
        int cmd;
        int val2;
        if ((futex_op & FUTEX_PRIVATE) == 0) {
                BUG("futex sharing not supported\n");
                return -ENOSYS;
        }
        cmd = futex_op & FUTEX_CMD_MASK;

        switch (cmd) {
        case FUTEX_WAIT:
                return dfutex_wait(uaddr, futex_op, val, timeout);
        case FUTEX_WAKE:
                return dfutex_wake(uaddr, futex_op, val);
        case FUTEX_REQUEUE:
                val2 = (long)timeout;
                return dfutex_requeue(uaddr, uaddr2, val, val2);
        default:
                BUG("futex op not implemented\n");
        }
        return -ENOSYS;
}
#endif /* CHCORE_SPLIT_CONTAINER */

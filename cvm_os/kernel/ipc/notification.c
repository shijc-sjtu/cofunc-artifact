/*
 * Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <ipc/connection.h>
#include <ipc/notification.h>
#include <common/list.h>
#include <common/errno.h>
#include <object/thread.h>
#include <object/irq.h>
#include <sched/sched.h>
#include <sched/context.h>
#include <irq/irq.h>
#include <mm/uaccess.h>

void init_notific(struct notification *notifc)
{
        notifc->not_delivered_notifc_count = 0;
        notifc->waiting_threads_count = 0;
        init_list_head(&notifc->waiting_threads);
        lock_init(&notifc->notifc_lock);
        notifc->state = OBJECT_STATE_VALID;
#ifdef CHCORE_SPLIT_CONTAINER
#ifndef CHCORE_SPLIT_CONTAINER_SYNC
	notifc->sc_sem = NULL;
#endif /* CHCORE_SPLIT_CONTAINER_SYNC */
#endif /* CHCORE_SPLIT_CONTAINER */
}

void notification_deinit(void *ptr)
{
        /* No deinitialization is required for now. */
}

#ifdef CHCORE_SPLIT_CONTAINER
void notifc_clone(struct notification *dst_notifc,
                  struct notification *src_notifc,
                  struct cap_group *dst_cap_group)
{
        struct thread *src_thread;
        struct thread *dst_thread;
        
        dst_notifc->not_delivered_notifc_count =
                src_notifc->not_delivered_notifc_count;
        dst_notifc->waiting_threads_count =
                src_notifc->waiting_threads_count;
        init_list_head(&dst_notifc->waiting_threads);
        lock_init(&dst_notifc->notifc_lock);
        dst_notifc->state = src_notifc->state;

        for_each_in_list (src_thread, struct thread, notification_queue_node,
                          &src_notifc->waiting_threads) {
                dst_thread = obj_get(dst_cap_group, src_thread->cap, TYPE_THREAD);
                BUG_ON(!dst_thread || dst_thread->thread_ctx->state != TS_WAITING);
                obj_put(dst_thread);

                list_append(&dst_thread->notification_queue_node,
                            &dst_notifc->waiting_threads);
        }
}
#endif /* CHCORE_SPLIT_CONTAINER */

/*
 * A waiting thread can be awoken by timeout and signal, which leads to racing.
 * We guarantee that a thread is not awoken for twice by 1. removing a thread
 *from notification waiting_threads when timeout and 2. removing a thread from
 * sleep_list when get signaled.
 * When signaled:
 *	lock(notification)
 *	remove from waiting_threads
 *      thread state = TS_READY
 *	unlock(notification)
 *
 *	if (sleep_state.cb != NULL) {
 *		lock(sleep_list)
 *		if (sleep_state.cb != NULL)
 *			remove from sleep_list
 *		unlock(sleep_list)
 *	}
 *
 * When timeout:
 *	lock(sleep_list)
 *	remove from sleep_list
 *	lock(notification)
 *	if (thread state == TS_WAITING)
 *		remove from waiting_threads
 *	unlock(notification)
 *	sleep_state.cb = NULL
 *	unlock(sleep_list)
 */

static void notific_timer_cb(struct thread *thread)
{
        struct notification *notifc;

        notifc = thread->sleep_state.pending_notific;
        thread->sleep_state.pending_notific = NULL;

        lock(&notifc->notifc_lock);

        /* For recycling: the state is set in stop_notification */
        if (notifc->state == OBJECT_STATE_INVALID) {
                thread->thread_ctx->thread_exit_state = TE_EXITED;
                unlock(&notifc->notifc_lock);
                return;
        }

        if (thread->thread_ctx->state != TS_WAITING) {
                unlock(&notifc->notifc_lock);
                return;
        }

        list_del(&thread->notification_queue_node);
        BUG_ON(notifc->waiting_threads_count <= 0);
        notifc->waiting_threads_count--;

        arch_set_thread_return(thread, -ETIMEDOUT);
        thread->thread_ctx->state = TS_INTER;
        BUG_ON(sched_enqueue(thread));

        unlock(&notifc->notifc_lock);
}

/* Return 0 if wait successfully, -EAGAIN otherwise */
int wait_notific(struct notification *notifc, bool is_block,
                 struct timespec *timeout)
{
        int ret = 0;
        struct thread *thread;

        lock(&notifc->notifc_lock);

        /* For recycling: the state is set in stop_notification */
        if (notifc->state == OBJECT_STATE_INVALID) {
                unlock(&notifc->notifc_lock);
                return -ECAPBILITY;
        }

        if (notifc->not_delivered_notifc_count > 0) {
                notifc->not_delivered_notifc_count--;
                ret = 0;
        } else {
                if (is_block) {
                        thread = current_thread;
                        /*
                         * queue_lock: grab the lock and then insert/remove
                         * a thread into one list.
                         */

                        lock(&thread->sleep_state.queue_lock);

                        /* Add this thread to waiting list */
                        list_append(&thread->notification_queue_node,
                                    &notifc->waiting_threads);
                        thread->thread_ctx->state = TS_WAITING;
                        notifc->waiting_threads_count++;
                        arch_set_thread_return(thread, 0);

                        if (timeout) {
                                thread->sleep_state.pending_notific = notifc;
                                enqueue_sleeper(
                                        thread, timeout, notific_timer_cb);
                        }

                        /*
                         * Since current_thread is TS_WAITING,
                         * sched() will not put current_thread into the
                         * ready_queue.
                         *
                         * sched() must executed before unlock.
                         * Otherwise, current_thread maybe be notified and then
                         * its state will be set to TS_RUNNING. If so, sched()
                         * will put it into the ready_queue and it maybe
                         * directly switch to.
                         */
                        sched();

                        unlock(&thread->sleep_state.queue_lock);

                        unlock(&notifc->notifc_lock);

                        /* See the below impl of sys_notify */
                        obj_put(notifc);

                        eret_to_thread(switch_context());
                        /* The control flow will never reach here */

                } else {
                        ret = -EAGAIN;
                }
        }
        unlock(&notifc->notifc_lock);
        return ret;
}

void wait_irq_notific(struct irq_notification *irq_notifc)
{
        struct notification *notifc;

        notifc = &(irq_notifc->notifc);
        lock(&notifc->notifc_lock);

        /* Add this thread to waiting list */
        list_append(&current_thread->notification_queue_node,
                    &notifc->waiting_threads);
        current_thread->thread_ctx->state = TS_WAITING;
        notifc->waiting_threads_count++;
        arch_set_thread_return(current_thread, 0);

        irq_notifc->user_handler_ready = 1;

        sched();

        unlock(&notifc->notifc_lock);

        eret_to_thread(switch_context());
        /* The control flow will never reach here */
}

void signal_irq_notific(struct irq_notification *irq_notifc)
{
        struct notification *notifc;
        struct thread *target;

        notifc = &(irq_notifc->notifc);

        lock(&notifc->notifc_lock);

        irq_notifc->user_handler_ready = 0;

        /*
         * Some threads have been blocked and waiting for notifc.
         * Wake up one waiting thread
         */
        target = list_entry(notifc->waiting_threads.next,
                            struct thread,
                            notification_queue_node);
        list_del(&target->notification_queue_node);
        notifc->waiting_threads_count--;

        BUG_ON(target->thread_ctx->sc == NULL);

        unlock(&notifc->notifc_lock);
        obj_put(irq_notifc);

        target->thread_ctx->state = TS_INTER;
        BUG_ON(sched_enqueue(target));

        sched_periodic();
        eret_to_thread(switch_context());
}

void try_remove_timeout(struct thread *target)
{
        if (target == NULL)
                return;
        if (target->sleep_state.cb == NULL)
                return;

        try_dequeue_sleeper(target);

        target->sleep_state.pending_notific = NULL;
}

int signal_notific(struct notification *notifc)
{
        struct thread *target = NULL;

        lock(&notifc->notifc_lock);

        /* For recycling: the state is set in stop_notification */
        if (notifc->state == OBJECT_STATE_INVALID) {
                unlock(&notifc->notifc_lock);
                return -ECAPBILITY;
        }

        if (notifc->not_delivered_notifc_count > 0
            || notifc->waiting_threads_count == 0) {
                notifc->not_delivered_notifc_count++;
        } else {
                /*
                 * Some threads have been blocked and waiting for notifc.
                 * Wake up one waiting thread
                 */
                target = list_entry(notifc->waiting_threads.next,
                                    struct thread,
                                    notification_queue_node);

                BUG_ON(target == NULL);

                /*
                 * signal_notific may return -EAGAIN because of unable to lock.
                 * The user-level library will transparently notify again.
                 *
                 * This is for preventing dead lock because handler_timer_irq
                 * may already grab the queue_lock of a thread or the sleep_list
                 * lock.
                 */
                if (try_lock(&target->sleep_state.queue_lock) != 0) {
                        /* Lock failed: must be timeout now */
                        unlock(&notifc->notifc_lock);
                        return -EAGAIN;
                }

                /* cb != NULL indicates the thread is also in the sleep list */
                if (target->sleep_state.cb != NULL) {
                        if (try_dequeue_sleeper(target) == false) {
                                /* Failed to remove target in sleep list */
                                unlock(&target->sleep_state.queue_lock);
                                unlock(&notifc->notifc_lock);
                                return -EAGAIN;
                        }
                }

                /* Delete the thread from the waiting list of the notification
                 */
                list_del(&target->notification_queue_node);
                notifc->waiting_threads_count--;

                target->thread_ctx->state = TS_INTER;
                BUG_ON(sched_enqueue(target));

                unlock(&target->sleep_state.queue_lock);
        }

        unlock(&notifc->notifc_lock);

        return 0;
}

cap_t sys_create_notifc(void)
{
        struct notification *notifc = NULL;
        cap_t notifc_cap = 0;
        int ret = 0;

        notifc = obj_alloc(TYPE_NOTIFICATION, sizeof(*notifc));
        if (!notifc) {
                ret = -ENOMEM;
                goto out_fail;
        }
        init_notific(notifc);

        notifc_cap = cap_alloc(current_cap_group, notifc);
        if (notifc_cap < 0) {
                ret = notifc_cap;
                goto out_free_obj;
        }

        return notifc_cap;

out_free_obj:
        obj_free(notifc);
out_fail:
        return ret;
}

int sys_wait(cap_t notifc_cap, bool is_block, struct timespec *timeout)
{
        struct notification *notifc;
        struct timespec timeout_k;
        int ret;

        notifc = obj_get(current_thread->cap_group, notifc_cap, TYPE_NOTIFICATION);
        if (!notifc) {
                ret = -ECAPBILITY;
                goto out;
        }

        if (timeout) {
                ret = copy_from_user(
                        (char *)&timeout_k, (char *)timeout, sizeof(timeout_k));
                if (ret != 0)
                        goto out_obj_put;
        }

        ret = wait_notific(notifc, is_block, timeout ? &timeout_k : NULL);
out_obj_put:
        obj_put(notifc);
out:
        return ret;
}

int sys_notify(cap_t notifc_cap)
{
        struct notification *notifc;
        int ret;
        notifc = obj_get(
                current_thread->cap_group, notifc_cap, TYPE_NOTIFICATION);
        if (!notifc) {
                ret = -ECAPBILITY;
                goto out;
        }
        ret = signal_notific(notifc);
        obj_put(notifc);
out:
        return ret;
}

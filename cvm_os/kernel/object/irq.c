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

#include <arch/sync.h>
#include <ipc/notification.h>
#include <irq/irq.h>
#include <object/irq.h>
#include <common/errno.h>
#include <sched/context.h>

struct irq_notification *irq_notifcs[MAX_IRQ_NUM];
int user_handle_irq(int irq)
{
        struct irq_notification *irq_notic;

        irq_notic = irq_notifcs[irq];
        BUG_ON(!irq_notic);

        /*
         * If the interrupt handler thread is not ready for handling a new
         * interrupt, we ignore a nested interrupt.
         */
        if (!irq_notic->user_handler_ready) {
                kdebug("One interrupt (irq: %d) is ingored since the handler "
                       "thread is not ready.\n",
                       irq);
                return 0;
        }

        /*
         * Disable the irq before passing the current irq to the
         * user-level handler thread.
         */
        arch_disable_irqno(irq_notic->intr_vector);

        signal_irq_notific(irq_notic);
        /* Never returns. */

        BUG_ON(1);
        __builtin_unreachable();
}

void irq_deinit(void *irq_ptr)
{
        struct irq_notification *irq_notifc;
        int irq;

        irq_notifc = (struct irq_notification *)irq_ptr;
        irq = irq_notifc->intr_vector;
        irq_handle_type[irq] = HANDLE_KERNEL;
        smp_mb();
        irq_notifcs[irq] = NULL;
}

cap_t sys_irq_register(int irq)
{
        struct irq_notification *irq_notifc = NULL;
        cap_t irq_notifc_cap = 0;
        int ret = 0;

        if (irq < 0 || irq >= MAX_IRQ_NUM)
                return -EINVAL;

        irq_notifc = obj_alloc(TYPE_IRQ, sizeof(*irq_notifc));
        if (!irq_notifc) {
                ret = -ENOMEM;
                goto out_fail;
        }
        irq_notifc->intr_vector = irq;
        init_notific(&irq_notifc->notifc);
        irq_notifc->user_handler_ready = 0;

        irq_notifc_cap = cap_alloc(current_cap_group, irq_notifc);
        if (irq_notifc_cap < 0) {
                ret = irq_notifc_cap;
                goto out_free_obj;
        }

        irq_notifcs[irq] = irq_notifc;
        smp_mb();
        irq_handle_type[irq] = HANDLE_USER;

        return irq_notifc_cap;
out_free_obj:
        obj_free(irq_notifc);
out_fail:
        return ret;
}

int sys_irq_wait(cap_t irq_cap, bool is_block)
{
        struct irq_notification *irq_notifc;
        int ret = 0;
        irq_notifc = obj_get(current_thread->cap_group, irq_cap, TYPE_IRQ);
        if (!irq_notifc) {
                ret = -ECAPBILITY;
                goto out;
        }

        /*
         * When the interrupt handler thread calls this function,
         * we enable the corresponding irq.
         */
        arch_enable_irqno(irq_notifc->intr_vector);
        wait_irq_notific(irq_notifc);

        /* Never returns */
        BUG_ON(1);

out:
        return ret;
}

int sys_irq_ack(cap_t irq_cap)
{
        struct irq_notification *irq_notifc;
        int ret = 0;
        irq_notifc = obj_get(current_thread->cap_group, irq_cap, TYPE_IRQ);
        if (!irq_notifc) {
                ret = -ECAPBILITY;
                goto out;
        }
        plat_ack_irq(irq_notifc->intr_vector);
        obj_put(irq_notifc);
out:
        return ret;
}

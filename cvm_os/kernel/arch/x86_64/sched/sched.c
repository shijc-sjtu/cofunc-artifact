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

#include <sched/sched.h>
#include <arch/sched/arch_sched.h>
#include <arch/machine/registers.h>
#include <object/thread.h>
#include <common/vars.h>
#include <arch/machine/smp.h>
#include <mm/kmalloc.h>
#include <lib/printk.h>
#include <seg.h>

void arch_idle_ctx_init(struct thread_ctx *idle_ctx, void (*func)(void))
{
	int i = 0;
	arch_exec_ctx_t *ec = &(idle_ctx->ec);

	/* set general registers to zero */
	for (i = 0; i < REG_NUM; i++)
		ec->reg[i] = 0;

	ec->reg[DS] = KDSEG;
	ec->reg[RIP] = (u64) func;
	ec->reg[CS] = KCSEG64;
	ec->reg[RFLAGS] = EFLAGS_DEFAULT;

	ec->reg[RSP] = (u64)((char *)idle_ctx + sizeof(arch_exec_ctx_t));
	ec->reg[SS] = KDSEG;
}

void arch_switch_context(struct thread *target)
{
	arch_exec_ctx_t * cur_exec_ctx;
	vaddr_t interrupt_stack;

	/* Get the addr of the execution context */
	cur_exec_ctx = &(target->thread_ctx->ec);
	/*
	 * Set the `cur_exec_ctx` in the per_cpu info
	 * whose base addr is stored in GS
	 */
	asm volatile ("movq %0, %%gs:%c1"
		      :
		      :"r" (cur_exec_ctx),
		      "i"(OFFSET_CURRENT_EXEC_CTX)
		      //"i"(offsetof(struct per_cpu_info, cur_exec_ctx))
		      :"memory");

	/* Get the addr of the interrupt stack */
	interrupt_stack = ((vaddr_t)cur_exec_ctx) + sizeof(arch_exec_ctx_t);

	/*
	 * Set the interrupt stack. Same as:
	 *
	 * cpuid = smp_get_cpu_id();
	 * tss = &(cpu_info[cpuid].tss);
	 * tss->rsp[0] = interrupt_stack;
	 */
	asm volatile ("movq %0, %%gs:%c1"
		      :
		      :"r" (interrupt_stack),
		      "i"(OFFSET_CURRENT_INTERRUPT_STACK)
		      :"memory");

}

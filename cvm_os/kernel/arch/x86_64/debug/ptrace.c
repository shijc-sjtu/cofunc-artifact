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

#include <object/thread.h>
#include <machine.h>
#include <arch/machine/registers.h>
#include <common/util.h>


int arch_ptrace_getregs(struct thread *thread,
			struct chcore_user_regs_struct *user_regs)
{
        unsigned long *regs = thread->thread_ctx->ec.reg;

	memcpy(user_regs, regs, 8 * REG_NUM);
	user_regs->fs_base = thread->thread_ctx->tls_base_reg[TLS_FS];
	user_regs->gs_base = thread->thread_ctx->tls_base_reg[TLS_GS];

	/* Not supported */
	user_regs->dummy_reserved = 0;
	user_regs->dummy_ec = 0;
	user_regs->trapno = 0;
	user_regs->es = 0;
	user_regs->fs = 0;
	user_regs->gs = 0;

	return 0;
}

int arch_ptrace_getreg(struct thread *thread, unsigned long addr,
		       unsigned long *val)
{
	addr /= sizeof(long);

	if (addr >= REG_NUM)
		return -EINVAL;
	if (addr == RESERVE || addr == TRAPNO)
		return -EINVAL;

	*val = thread->thread_ctx->ec.reg[addr];
	return 0;
}

int arch_ptrace_setreg(struct thread *thread, unsigned long addr,
		       unsigned long data)
{
	addr /= sizeof(long);

	if (addr >= REG_NUM)
		return -EINVAL;
	if (addr == RESERVE || addr == TRAPNO)
		return -EINVAL;

	thread->thread_ctx->ec.reg[addr] = data;
	return 0;
}

int arch_set_thread_singlestep(struct thread *thread, bool step)
{
	if (step)
		thread->thread_ctx->ec.reg[RFLAGS] |= EFLAGS_TF;
	else
		thread->thread_ctx->ec.reg[RFLAGS] &= ~EFLAGS_TF;
	return 0;
}

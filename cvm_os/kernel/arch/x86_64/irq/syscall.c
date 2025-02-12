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

#include <seg.h>
#include <arch/machine/registers.h>
#include <machine.h>
#include "irq_entry.h"

void arch_syscall_init(void)
{
	u64 star;

	star = ((((u64)UCSEG | 0x3) - 16) << 48) | ((u64)KCSEG64 << 32);
	wrmsr(MSR_STAR, star);
	/* setup syscall entry point */
	wrmsr(MSR_LSTAR, (u64)&sys_entry);
	wrmsr(MSR_SFMASK, EFLAGS_TF | EFLAGS_IF);
}

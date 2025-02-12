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

#include <common/debug.h>
#include <common/kprint.h>
#include <common/types.h>
#include <object/thread.h>
#include <mm/uaccess.h>

int set_backtrace_data(void *pc_buf, void *fp_buf, void *ip)
{
#if ENABLE_BACKTRACE_FUNC == ON
	kinfo("backtrace on x86_64 is not enabled\n");
#endif
	return 0;
}

int backtrace(void)
{
#if ENABLE_BACKTRACE_FUNC == ON
	u64 rbp, rip;
	struct vmregion *vmr;

	/*
	 * backtrace on x86_64 currently supports programs compiled with
	 * -fno-omit-frame-pointer and in user space
	 */
	kinfo("user backtrace:\n");
	kinfo("\t0x%lx\n", current_thread->thread_ctx->ec.reg[RIP]);

	rbp = current_thread->thread_ctx->ec.reg[RBP];
	disable_smap();
	while (1) {
		/*
		 * Why find_vmr_for_va instead of copy_from_user:
		 * Copy_from_user handles invalid access.
		 * But the function may be called with vmspace_lock
		 * held. The page fault triggered by copy_from_user
		 * may cause deadlock
		 */
		vmr = find_vmr_for_va(current_thread->vmspace, (vaddr_t)rbp);
		if (!vmr)
			break;
		rip = *(u64 *)(rbp + 8);
		rbp = *(u64 *)rbp;

		kinfo("\t0x%lx\n", rip);
	}
	enable_smap();
#endif
	return 0;
}

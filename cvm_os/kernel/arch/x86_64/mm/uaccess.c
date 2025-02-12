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

#include <common/util.h>
#include <common/vars.h>
#include <common/types.h>
#include <common/kprint.h>
#include <common/macro.h>
#include <mm/kmalloc.h>
#include <mm/vmspace.h>
#include <mm/mm.h>
#include <object/thread.h>
#include <object/object.h>
#include <object/cap_group.h>
#include <machine.h>

#ifndef FBINFER

int copy_from_user(void *kernel_buf, const void *user_buf, size_t size)
{
	/* validate user_buf */
	BUG_ON((u64)user_buf >= KBASE);
	disable_smap();
	memcpy(kernel_buf, user_buf, size);
	enable_smap();
	return 0;
}

int copy_to_user(void *user_buf, const void *kernel_buf, size_t size)
{
	/* validate user_buf */
	BUG_ON((u64)user_buf >= KBASE);
	disable_smap();
	memcpy(user_buf, kernel_buf, size);
	enable_smap();
	return 0;
}

int copy_string_from_user(void *kernel_buf, const void *user_buf, size_t size)
{
	size_t len;
	/* validate user_buf */
	BUG_ON((u64)user_buf >= KBASE);
	disable_smap();
	len = strlen(user_buf);
	BUG_ON(len >= size);
	memcpy(kernel_buf, user_buf, len + 1);
	enable_smap();
	return 0;
}

#endif

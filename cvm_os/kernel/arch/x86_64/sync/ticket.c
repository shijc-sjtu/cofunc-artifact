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

#include <common/types.h>
#include <common/errno.h>
#include <common/macro.h>
#include <common/lock.h>
#include <common/kprint.h>
#include <arch/sync.h>

#include "ticket.h"

int lock_init(struct lock *l)
{
	struct lock_impl *lock = (struct lock_impl *)l;
	BUG_ON(!lock);
	/* Initialize ticket lock */
	lock->owner = 0;
	lock->next = 0;
	return 0;
}

void lock(struct lock *l)
{
	struct lock_impl *lock = (struct lock_impl *)l;
	u32 lockval = 0;

	BUG_ON(!lock);
	lockval = atomic_fetch_add_32(&lock->next, 1);
	while (lockval != lock->owner) CPU_PAUSE();
	COMPILER_BARRIER();
}

int try_lock(struct lock *l)
{
	struct lock_impl *lock = (struct lock_impl *)l;
	volatile u32 newval;
	int ret = 0;

	BUG_ON(!lock);
	newval = lock->next;
	if (lock->owner != newval
	    || compare_and_swap_32((s32 *) & lock->next, newval,
					       newval + 1) != newval)
		ret = -1;
	COMPILER_BARRIER();
	return ret;
}

void unlock(struct lock *l)
{
	struct lock_impl *lock = (struct lock_impl *)l;

	BUG_ON(!lock);
	COMPILER_BARRIER();
	lock->owner = lock->owner + 1;
}

int is_locked(struct lock *l)
{
	struct lock_impl *lock = (struct lock_impl *)l;

	return lock->owner < lock->next;
}

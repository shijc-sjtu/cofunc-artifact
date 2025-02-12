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

/* Simple RWLock */

int rwlock_init(struct rwlock *rwlock)
{
	if (rwlock == 0)
		return -EINVAL;
	rwlock->lock = 0;
	return 0;
}

/* WARN: when there are more than 0x7FFFFFFF readers exist, this function
 * will not function correctly */
void read_lock(struct rwlock *rwlock)
{
	while (atomic_fetch_add_32((s32 *)&rwlock->lock, 1) & 0x80000000) {
		while(rwlock->lock & 0x80000000)
			CPU_PAUSE();
	}
	COMPILER_BARRIER();
}

int read_try_lock(struct rwlock *rwlock)
{
	s32 old;

	old = atomic_fetch_add_32((s32 *)&rwlock->lock, 1);
	COMPILER_BARRIER();
	return (old & 0x80000000)? -1: 0;
}

void read_unlock(struct rwlock *rwlock)
{
	COMPILER_BARRIER();
	atomic_fetch_add_32(&rwlock->lock, -1);
}

void write_lock(struct rwlock *rwlock)
{
	while(compare_and_swap_32((s32 *)&rwlock->lock, 0, 0x80000000) != 0)
		CPU_PAUSE();
	COMPILER_BARRIER();
}

int write_try_lock(struct rwlock *rwlock)
{
	int ret = 0;

	if(compare_and_swap_32((s32 *)&rwlock->lock, 0, 0x80000000) != 0)
		ret = -1;
	COMPILER_BARRIER();
	return ret;
}


void write_unlock(struct rwlock *rwlock)
{
	COMPILER_BARRIER();
	rwlock->lock = 0;
}

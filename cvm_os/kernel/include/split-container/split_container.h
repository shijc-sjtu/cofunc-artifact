#pragma once

#include <common/types.h>
#include <object/thread.h>

#if defined(CHCORE_PLAT_INTEL_TDX)
#define VMCALL_SC_VCPU_IDLE     0x10010
#define VMCALL_SC_REQUEST       0x10011
#elif defined(CHCORE_PLAT_AMD_SEV)
#define VMCALL_SC_VCPU_IDLE     100
#define VMCALL_SC_REQUEST       101
#endif

#define SC_REQ_DEBUG_PUTC       1
#define SC_REQ_GET_MEM_SIZE     2
#define SC_REQ_GRANT_MEM        3
#define SC_REQ_WITH_SHM         4
#define SC_REQ_VCPU_PAUSE       5
#define SC_REQ_ACTIVATE_THREAD  6
#define SC_REQ_MAP_GPA          7
#define SC_REQ_START_POLLING    8
#define SC_REQ_ADD_POLLING      9
#define SC_REQ_GET_TID          10
#define SC_REQ_WAKE_THREAD      11
#define SC_REQ_SYNC_IS_ENABLED  12
#define SC_REQ_SEM_POST         13
#define SC_REQ_WAIT_FINISH	14

#define SC_SHM_SIZE              0x200000
#define SC_SHM_MAX_ARGC          16
#define SC_SHM_MAX_DATA_LEN      (SC_SHM_SIZE - sizeof(struct sc_shm))

long sys_split_container(int op, long a, long b, long c, long d);

long split_container_request(int op, long a, long b);

void split_container_thread_init(struct thread *thread);

void split_container_thread_deinit(struct thread *thread);

void split_container_cap_group_init(struct cap_group *cap_group);

void split_container_cap_group_deinit(struct cap_group *cap_group);

int split_container_notify_recycler(struct cap_group *cap_group);

void *split_container_get_pages(int order, int enc);

int split_container_free_pages(void *addr);

void split_container_vcpu_pause(void);

long split_container_activate_thread(struct thread *thread, bool new_vcpu);

#ifndef CHCORE_SPLIT_CONTAINER_SYNC
void split_container_flush_remote_tlb(u32 target_cpu, vaddr_t start_va,
				      u64 page_cnt, u64 pcid, u64 vmspace);
#endif /* CHCORE_SPLIT_CONTAINER_SYNC */

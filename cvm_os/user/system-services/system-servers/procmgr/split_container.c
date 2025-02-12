#ifdef CHCORE_SPLIT_CONTAINER
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <chcore/syscall.h>
#include <chcore/sc_shm.h>
#include "srvmgr.h"
#include "proc_node.h"

#if defined(CHCORE_PLAT_AMD_SEV)
#define PLAT_CPU_NUM 96
#elif defined(CHCORE_PLAT_INTEL_TDX)
#define PLAT_CPU_NUM 128
#endif
#define PLAT_CPU_POOL_BASE 4

#define debug(fmt, ...) // printf(fmt, ##__VA_ARGS__)

int usys_cap_group_recycle(int);

static void *vcpu_loop(void *arg)
{
        int cpuid = (int)(long)arg;
        unsigned long thread;
        int argc, i;
        char *argv[SC_SHM_MAX_ARGC];
        struct proc_node *proc;
        cap_t shm_pmo_cap;
        struct sc_shm *shm;
        unsigned long t_sc_init_overhead;

        usys_set_affinity(0, cpuid);
        usys_yield();

        for (;;) {
                thread = usys_split_container(SYS_SC_OP_VCPU_IDLE, 0, 0, 0, 0);
                
                if (!thread) {
                        t_sc_init_overhead =
                                usys_split_container(SYS_SC_OP_INIT_MEM, 0, 0, 0, 0);
                } else {
                        usys_split_container(SYS_SC_OP_BIND_THREAD, thread, 0, 0, 0);
                }

                if (!thread) {
                        shm_pmo_cap = usys_create_pmo(SC_SHM_SIZE, PMO_SC_SHM);
                        shm = chcore_auto_map_pmo(shm_pmo_cap, SC_SHM_SIZE, VM_READ | VM_WRITE);

                        shm->req = SC_SHM_REQ_GET_ARG;
                        shm->time = t_sc_init_overhead;
                        usys_split_container(SYS_SC_OP_SHM_REQ, shm_pmo_cap, 0, 0, 0);
                        argc = shm->get_arg.argc;
                        for (i = 0; i < argc; i++) {
                                argv[i] = shm->data + shm->get_arg.argv[i];
                        }

                        for (i = 0; i < argc; i++) {
                                debug("[SC-G] get_args: argv[%d]=%s\n", i, argv[i]);
                        }

                        debug("[SC-G] get_args: argc=%d\n", argc);

                        if (argc > 0) {
                                proc = procmgr_launch_process(argc, argv, strdup("enclave"), false, 0, COMMON_APP);
                                BUG_ON(!proc);
                        } else {
                                debug("Restore!!!\n");
                                proc = new_proc_node(NULL, strdup("enclave"), COMMON_APP);
                                BUG_ON(!proc);
                                proc->state = PROC_STATE_RUNNING;
                                proc->proc_cap = usys_split_container(SYS_SC_OP_RESTORE, proc->badge, proc->pcid, 0, 0);
                        }

                        chcore_auto_unmap_pmo(shm_pmo_cap, (unsigned long)shm, SC_SHM_SIZE);
                        usys_revoke_cap(shm_pmo_cap, false);
                }

                if (!thread) {
                        usys_split_container(SYS_SC_OP_RECYCLE_WAIT, proc->proc_cap, 0, 0, 0);
                        debug("[SC-G] recycle_wait: return cap=%d\n", proc->proc_cap);
                        proc->state = PROC_STATE_EXIT;
                        while (usys_cap_group_recycle(proc->proc_cap) == -EAGAIN) {
#ifndef CHCORE_SPLIT_CONTAINER_SYNC
                                usys_split_container(SYS_SC_OP_WAKE_ALL, proc->proc_cap, 0, 0, 0);
#endif /* CHCORE_SPLIT_CONTAINER_SYNC */
                                usys_yield();
                        }
                        debug("[SC-G] cap_group_recycle done\n");
                        del_proc_node(proc);
                }
                while (usys_split_container(SYS_SC_OP_WAIT_IDLE, 0, 0, 0, 0)) {
                        usys_yield();
                }

                if (!thread) {
                        usys_split_container(SYS_SC_OP_DEINIT_MEM, 0, 0, 0, 0);
                }
        }

        return NULL;
}

void split_container_init(void)
{
        int cpuid;
        pthread_t pthread;

        for (cpuid = PLAT_CPU_POOL_BASE; cpuid < PLAT_CPU_NUM; cpuid++) {
                pthread_create(&pthread, NULL, vcpu_loop, (void *)(long)cpuid);
        }
}
#endif /* CHCORE_SPLIT_CONTAINER */

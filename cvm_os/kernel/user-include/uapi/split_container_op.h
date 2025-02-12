#pragma once

#define SYS_SC_OP_VCPU_IDLE     1
#define SYS_SC_OP_INIT_MEM      2
#define SYS_SC_OP_DEINIT_MEM    3
#define SYS_SC_OP_INIT_SHM      4
#define SYS_SC_OP_DEINIT_SHM    5
#define SYS_SC_OP_GET_ARGS      6
#define SYS_SC_OP_WAIT_IDLE     7
#define SYS_SC_OP_RECYCLE_WAIT  8
#define SYS_SC_OP_IS_ENCLAVE    9
#define SYS_SC_OP_GET_SHM       10
#define SYS_SC_OP_SHM_REQ       11
#define SYS_SC_OP_SNAPSHOT      12
#define SYS_SC_OP_RESTORE       13
#define SYS_SC_OP_BIND_THREAD   14
#define SYS_SC_OP_PRINT_STAT    15
#define SYS_SC_OP_REG_T_PGFAULT  16
#define SYS_SC_OP_START_POLLING 17
#define SYS_SC_OP_ADD_POLLING   18
#define SYS_SC_OP_REG_DEFER_SCHED  19
#define SYS_SC_OP_SET_SEM       20
#define SYS_SC_OP_GET_SEM       21
#define SYS_SC_OP_SYNC_IS_ENABLED 22
#define SYS_SC_OP_SIGNAL_ALL_NOTIFCS 23
#define SYS_SC_OP_WAKE_ALL      24
#define SYS_SC_OP_GET_STAT      25
#define SYS_SC_OP_WAIT_FINISH   26

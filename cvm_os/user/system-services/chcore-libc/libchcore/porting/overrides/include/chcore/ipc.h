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

#pragma once

#include <chcore/type.h>
#include <chcore/defs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Starts from 1 because the uninitialized value is 0 */
enum system_server_identifier {
        FS_MANAGER = 1,
        NET_MANAGER,
        PROC_MANAGER,
};

/*
 * ipc_struct is created in **ipc_register_client** and
 * thus only used at client side.
 */
typedef struct ipc_struct {
        /* Connection_cap: used to call a server */
        cap_t conn_cap;
        /* Shared memory: used to create ipc_msg (client -> server) */
        unsigned long shared_buf;
        unsigned long shared_buf_len;

        /* A spin lock: used to coordinate the access to shared memory */
        volatile int lock;
        enum system_server_identifier server_id;
} ipc_struct_t;

extern cap_t fsm_server_cap;
extern cap_t lwip_server_cap;
extern cap_t procmgr_server_cap;
extern int init_process_in_lwip;
extern int init_lwip_lock;

/* ipc_struct for invoking system servers.
 * fsm_ipc_struct and lwip_ipc_struct are two addresses.
 * They can be used like **const** pointers.
 *
 * If a system server is related to the scalability (multi-threads) of
 * applications, we should use the following way to make the connection with it
 * as per-thread.
 *
 * For other system servers (e.g., process manager), it is OK to let multiple
 * threads share a same connection.
 */
ipc_struct_t *__fsm_ipc_struct_location(void);
ipc_struct_t *__net_ipc_struct_location(void);
ipc_struct_t *__procmgr_ipc_struct_location(void);
#define fsm_ipc_struct     (__fsm_ipc_struct_location())
#define lwip_ipc_struct    (__net_ipc_struct_location())
#define procmgr_ipc_struct (__procmgr_ipc_struct_location())

/* ipc_msg is located at ipc_struct->shared_buf. */
typedef struct ipc_msg {
        unsigned int data_len;
        /*
         * cap_slot_number represents the number of caps of the ipc_msg.
         * This is useful for both sending IPC and returning from IPC.
         * When calling ipc_return, cap_slot_number will be set 0 automatically,
         * indicating that no cap will be sent.
         * If you want to send caps when returning from IPC,
         * use ipc_return_with_cap.
         */
        unsigned int cap_slot_number;
        unsigned int data_offset;

#if __SIZEOF_POINTER__ == 8
        /* ipc_msg should be alligned to 8 bytes */
        unsigned int padding;
#endif

        /* icb: ipc control block (not needed by the kernel) */
        ipc_struct_t *icb;
} ipc_msg_t;

#define IPC_SHM_AVAILABLE (IPC_PER_SHM_SIZE - sizeof(ipc_msg_t))

/*
 * server_handler is an IPC routine (can have two arguments):
 * first is ipc_msg and second is client_badge.
 */
typedef void (*server_handler)();
typedef void (*server_destructor)(badge_t);

/* Registeration interfaces */
ipc_struct_t *ipc_register_client(cap_t server_thread_cap);

void *register_cb(void *ipc_handler);
void *register_cb_single(void *ipc_handler);

#define DEFAULT_CLIENT_REGISTER_HANDLER register_cb
#define DEFAULT_DESTRUCTOR              NULL

int ipc_register_server(server_handler server_handler,
                        void *(*client_register_handler)(void *));
int ipc_register_server_with_destructor(server_handler server_handler,
                                        void *(*client_register_handler)(void *),
                                        server_destructor server_destructor);

/* IPC message operating interfaces */
ipc_msg_t *ipc_create_msg(ipc_struct_t *icb, unsigned int data_len);
ipc_msg_t *ipc_create_msg_with_cap(ipc_struct_t *icb, unsigned int data_len, unsigned int cap_slot_number);
char *ipc_get_msg_data(ipc_msg_t *ipc_msg);
cap_t ipc_get_msg_cap(ipc_msg_t *ipc_msg, unsigned int cap_id);
int ipc_set_msg_data(ipc_msg_t *ipc_msg, void *data, unsigned int offset, unsigned int len);
int ipc_set_msg_cap(ipc_msg_t *ipc_msg, unsigned int cap_slot_index, cap_t cap);
int ipc_destroy_msg(ipc_msg_t *ipc_msg);

/* IPC issue/finish interfaces */
long ipc_call(ipc_struct_t *icb, ipc_msg_t *ipc_msg);
_Noreturn void ipc_return(ipc_msg_t *ipc_msg, long ret);
_Noreturn void ipc_return_with_cap(ipc_msg_t *ipc_msg, long ret);
int ipc_client_close_connection(ipc_struct_t *ipc_struct);

int simple_ipc_forward(ipc_struct_t *ipc_struct, void *data, int len);

/*
 * Magic number for coordination between client and server:
 * the client should wait until the server has reigsterd the service.
 */
#define NONE_INFO ((void *)(-1UL))

#ifdef __cplusplus
}
#endif

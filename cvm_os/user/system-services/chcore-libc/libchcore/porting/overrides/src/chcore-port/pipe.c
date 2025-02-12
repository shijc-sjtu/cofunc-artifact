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

/* This file is depreciated. Pipe is no longer supported. */

#include <chcore/bug.h>
#include <chcore/type.h>
#include <chcore/thread.h>
#include <chcore/syscall.h>
#include <chcore/pthread.h>
#include <string.h>
#include <pthread.h>
#include <debug_lock.h>
#include "atomic.h"

#include "pipe.h"
#include "fd.h"

/* TODO: dynamic size */
#define PIPE_BUF_SIZE 1024
struct pipe_file {
        char buf[PIPE_BUF_SIZE];
        /*
         * If read_idx == write_idx, the buffer is empty.
         * Thus the maximum size is PIPE_BUF_SIZE - 1.
         */
        int read_idx;
        int write_idx;
        int volatile pipe_lock;
        cap_t pipe_notifc;
        int read_fd;
        int write_fd;
#ifdef CHCORE_SPLIT_CONTAINER
        struct pollarg pollarg;
#endif /* CHCORE_SPLIT_CONTAINER */
};

static bool pipe_is_empty(struct pipe_file *pf)
{
        return pf->read_idx == pf->write_idx;
}

static bool pipe_is_full(struct pipe_file *pf)
{
        return PIPE_BUF_SIZE + pf->read_idx == pf->write_idx + 1;
}

static void pipe_notify_reader(struct pipe_file *pf)
{
        usys_notify(pf->pipe_notifc);
#ifdef CHCORE_SPLIT_CONTAINER
        if (pf->pollarg.poll_notifc >= 0 &&
            (pf->pollarg.events & (POLLIN | POLLRDNORM))) {
                usys_notify(pf->pollarg.poll_notifc);
                pf->pollarg.poll_notifc = -1;
        }
#endif /* CHCORE_SPLIT_CONTAINER */
}

static void pipe_notify_writer(struct pipe_file *pf)
{
        usys_notify(pf->pipe_notifc);
#ifdef CHCORE_SPLIT_CONTAINER
        if (pf->pollarg.poll_notifc >= 0 &&
            (pf->pollarg.events & (POLLOUT | POLLWRNORM))) {
                usys_notify(pf->pollarg.poll_notifc);
                pf->pollarg.poll_notifc = -1;
        }
#endif /* CHCORE_SPLIT_CONTAINER */
}

int chcore_pipe2(int pipefd[2], int flags)
{
        int read_fd, write_fd, ret;
        cap_t pipe_notifc;
        struct pipe_file *pf;
        struct fd_desc *read_fd_desc, *write_fd_desc;

        // if (flags != 0) {
        //         WARN("pipe2 flags not supported");
        //         return -ENOSYS;
        // }

        if ((pf = malloc(sizeof(*pf))) == NULL)
                return -ENOMEM;

        pipe_notifc = usys_create_notifc();
        if (pipe_notifc < 0) {
                ret = pipe_notifc;
                goto out_free_pf;
        }

        if ((read_fd = alloc_fd()) < 0) {
                ret = read_fd;
                goto out_free_pf;
        }

        read_fd_desc = fd_dic[read_fd];
        read_fd_desc->type = FD_TYPE_PIPE;
        read_fd_desc->private_data = pf;
        read_fd_desc->fd_op = &pipe_op;

        if ((write_fd = alloc_fd()) < 0) {
                ret = write_fd;
                goto out_free_read_fd;
        }

        write_fd_desc = fd_dic[write_fd];
        write_fd_desc->type = FD_TYPE_PIPE;
        write_fd_desc->private_data = pf;
        write_fd_desc->fd_op = &pipe_op;

        *pf = (struct pipe_file){.read_idx = 0,
                                 .write_idx = 0,
                                 .pipe_lock = 0,
                                 .pipe_notifc = pipe_notifc,
                                 .read_fd = read_fd,
                                 .write_fd = write_fd,
#ifdef CHCORE_SPLIT_CONTAINER
                                 .pollarg.poll_notifc = -1,
#endif /* CHCORE_SPLIT_CONTAINER */
                                 };

        pipefd[0] = read_fd;
        pipefd[1] = write_fd;

        return 0;

out_free_read_fd:
        free_fd(read_fd);

out_free_pf:
        free(pf);
        return ret;
}

static ssize_t chcore_pipe_read(int fd, void *buf, size_t count)
{
        struct pipe_file *pf;
        long r, len, len_tmp;

        if (fd < 0 || fd >= MAX_FD || fd_dic[fd]->type != FD_TYPE_PIPE)
                return -EINVAL;

        pf = fd_dic[fd]->private_data;
        chcore_spin_lock(&pf->pipe_lock);
        if (pf->read_fd != fd) {
                r = -EINVAL;
                goto out_unlock;
        }

        while (pipe_is_empty(pf)) {
                chcore_spin_unlock(&pf->pipe_lock);
                usys_wait(pf->pipe_notifc, true, NULL);
                chcore_spin_lock(&pf->pipe_lock);
        }

        if (pf->read_idx < pf->write_idx) {
                len = MIN(pf->write_idx - pf->read_idx, count);
                memcpy(buf, pf->buf, len);
                pf->read_idx += len;
                r = len;
        } else {
                /* total copied length */
                len = MIN(PIPE_BUF_SIZE - pf->read_idx + pf->write_idx, count);

                /* copy from read_idx to PIPE_BUF_SIZE */
                len_tmp = MIN(PIPE_BUF_SIZE - pf->read_idx, len);
                memcpy(buf, pf->buf, len_tmp);

                /* copy from 0 to write_idx */
                memcpy(buf, pf->buf + len_tmp, len - len_tmp);

                pf->read_idx = (pf->read_idx + len) % PIPE_BUF_SIZE;
                r = len;
        }

        pipe_notify_writer(pf);

out_unlock:
        chcore_spin_unlock(&pf->pipe_lock);
        return r;
}

static ssize_t chcore_pipe_write(int fd, void *buf, size_t count)
{
        struct pipe_file *pf;
        long r, len, len_tmp;

        if (fd < 0 || fd >= MAX_FD || fd_dic[fd]->type != FD_TYPE_PIPE)
                return -EINVAL;

        pf = fd_dic[fd]->private_data;
        chcore_spin_lock(&pf->pipe_lock);
        if (pf->write_fd != fd) {
                r = -EINVAL;
                goto out_unlock;
        }

        while (pipe_is_full(pf)) {
                chcore_spin_unlock(&pf->pipe_lock);
                usys_wait(pf->pipe_notifc, true, NULL);
                chcore_spin_lock(&pf->pipe_lock);
        }

        if (pf->read_idx <= pf->write_idx) {
                /* total copied length */
                len = MIN(PIPE_BUF_SIZE + pf->read_idx - pf->write_idx - 1,
                          count);

                /* copy to write_idx to PIPE_BUF_SIZE */
                len_tmp = MIN(PIPE_BUF_SIZE - pf->write_idx, len);
                memcpy(pf->buf, buf, len_tmp);

                /* copy to 0 to read_idx */
                memcpy(pf->buf + len_tmp, buf, len - len_tmp);

                pf->write_idx = (pf->write_idx + len) % PIPE_BUF_SIZE;
                r = len;
        } else {
                len = MIN(pf->read_idx - pf->write_idx, count);
                memcpy(pf->buf, buf, len);
                pf->write_idx += len;
                r = len;
        }

        pipe_notify_reader(pf);

out_unlock:
        chcore_spin_unlock(&pf->pipe_lock);
        return r;
}

static int chcore_pipe_close(int fd)
{
        struct pipe_file *pf;

        pf = fd_dic[fd]->private_data;
        if (fd == pf->read_fd) {
                pf->read_fd = -1;
                free_fd(fd);
        } else if (fd == pf->write_fd) {
                pf->write_fd = -1;
                free_fd(fd);
        } else {
                return -EBADF;
        }
        
        if (pf->read_fd == -1 && pf->write_fd == -1) {
                free(pf);
        }

        return 0;
}

static int chcore_pipe_poll(int fd, struct pollarg *arg)
{
        /* Already checked fd before call this function */
        BUG_ON(!fd_dic[fd]->private_data);
        int mask = 0;
        struct pipe_file *pf = fd_dic[fd]->private_data;

        /* Only check no need to lock */
        if (arg->events & POLLIN || arg->events & POLLRDNORM) {
                /* Check whether can read */
                mask |= !pipe_is_empty(pf) ? POLLIN | POLLRDNORM : 0;
        }

        /* Only check no need to lock */
        if (arg->events & POLLOUT || arg->events & POLLWRNORM) {
                /* Check whether can write */
                mask |= !pipe_is_full(pf) ? POLLOUT | POLLWRNORM : 0;
        }

#ifdef CHCORE_SPLIT_CONTAINER
        if (!mask) {
                pf->pollarg = *arg;
        }
#endif /* CHCORE_SPLIT_CONTAINER */

        return mask;
}

/* PIPE */
struct fd_ops pipe_op = {
        .read = chcore_pipe_read,
        .write = chcore_pipe_write,
        .close = chcore_pipe_close,
        .poll = chcore_pipe_poll,
        .ioctl = NULL,
        .fcntl = NULL,
};

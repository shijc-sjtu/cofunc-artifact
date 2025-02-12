#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

void libtmpfs_init(void);

int libtmpfs_open(const char *pathname, int flags, mode_t mode);

int libtmpfs_close(int fd);

int libtmpfs_mkdir(const char *pathname, mode_t mode);

int libtmpfs_rename(const char *oldpath, const char *newpath);

ssize_t libtmpfs_read(int fd, void *buf, size_t count);

ssize_t libtmpfs_write(int fd, const void *buf, size_t count);

int libtmpfs_fstat(int fd, struct stat *statbuf);

int libtmpfs_fstatat(int dirfd, const char *pathname, struct stat *statbuf,
                     int flags);

off_t libtmpfs_lseek(int fd, off_t offset, int whence);

int libtmpfs_getdents64(unsigned int fd, void *dirp, unsigned int count);

ssize_t libtmpfs_readv(int fd, const struct iovec *iov, int iovcnt);

ssize_t libtmpfs_writev(int fd, const struct iovec *iov, int iovcnt);

#ifndef LEAN_CONTAINER_H
#define LEAN_CONTAINER_H

// setup lean container, with an additional call to fork (a.k.a: double fork)
// so that the process is created in a new pid namespace
// if _namespace is less than 0, the container will run in a new namespace created by unshare
// otherwise the specified namespace is reused
int setup_lean_container_w_double_fork(char* name, char* rootfs_path, int _namespace);

#endif

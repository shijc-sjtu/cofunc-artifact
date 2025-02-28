#define _GNU_SOURCE
#include <sched.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <unistd.h>

#include "lean_container.h"

#define BUF_SIZE 256
#define DEFAULT_PERMISSION S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH

/* Cgroup V1 */
// char* cgroup_directory_prefix[] = {
//     "/sys/fs/cgroup/hugetlb/split_cntr/%s",
//     "/sys/fs/cgroup/perf_event/split_cntr/%s",
//     "/sys/fs/cgroup/net_cls,net_prio/split_cntr/%s",
//     "/sys/fs/cgroup/pids/split_cntr/%s",
//     "/sys/fs/cgroup/devices/split_cntr/%s",
//     "/sys/fs/cgroup/freezer/split_cntr/%s",
//     "/sys/fs/cgroup/cpu,cpuacct/split_cntr/%s",
//     "/sys/fs/cgroup/cpuset/split_cntr/%s",
//     "/sys/fs/cgroup/blkio/split_cntr/%s",
//     "/sys/fs/cgroup/memory/split_cntr/%s",
//     "/sys/fs/cgroup/systemd/split_cntr/%s",
//     NULL,
// };

/* Cgroup V2 */
char *cgroup_directory_prefix[] = {
    "/sys/fs/cgroup/split_container/%s",
    NULL,
};

// char* cpuset_cgroup_directory_prefix = "/sys/fs/cgroup/cpuset/split_cntr/%s";
// char* memory_cgroup_directory_prefix = "/sys/fs/cgroup/memory/split_cntr/%s";
// char* freezer_cgroup_directory_prefix = "/sys/fs/cgroup/freezer/split_cntr/%s";

// char* namespaces[] = {
//     "/proc/%d/ns/uts",
//     "/proc/%d/ns/pid",
//     "/proc/%d/ns/ipc",
//     "/proc/%d/ns/mnt",
//     NULL,
// };

// ============================== begin utility functions ==============================

// int set_namespace(int namespace) {
//     char buf[BUF_SIZE];
//     int fd, ret;
//     for (char** namespace_path = namespaces; *namespace_path != NULL; namespace_path++) {
//         sprintf(buf, *namespace_path, namespace);

//         fd = open(buf, O_RDONLY);
//         if (fd < 0) {
//             perror("open");
//             return -1;
//         }

//         ret = setns(fd, 0);
//         if (ret < 0) {
//             perror("setns");
//             return -1;
//         }

//         close(fd);
//     }
//     return 0;
// }

// writing pid to cgroup.procs under the cgroup directory will add the process to a cgroup
void cgroup_file_name(char* buf, const char* prefix, const char* name) {
    char path_buf[BUF_SIZE];
    sprintf(path_buf, prefix, name);
    sprintf(buf, "%s%s", path_buf, "/cgroup.procs");
}

// a wrapper to write pid to cgroupfs
int write_pid(pid_t pid, const char* cgroupfs_path) {
    char buf[BUF_SIZE];
    sprintf(buf, "%d", pid);
    size_t len = strlen(buf);
    
    int fd = open(cgroupfs_path, O_WRONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    ssize_t ret = write(fd, buf, len);
    if (ret != len) {
        fprintf(stderr, "write pid %s to %s returns %ld, expected %ld\n", buf, cgroupfs_path, ret, len);
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

// allow the process to run on numa node(s)
// int set_numa_cpuset(char* cpuset_root, int numa_start, int numa_end) {
//     char path_buf[BUF_SIZE];
//     sprintf(path_buf, "%s%s", cpuset_root, "/cpuset.mems");
    
//     // the following code does these things:
//     // echo 0-0 > /sys/fs/cgroup/.../cpuset.mems # process is allowed to run on numa node 0
//     // echo 0-1 > /sys/fs/cgroup/.../cpuset.mems # process is allowed to run on numa node 0 and 1
//     int fd = open(path_buf, O_WRONLY);
//     if (fd < 0) {
//         perror("open");
//         return -1;
//     }

//     // TODO: how to choose the numa node?
//     // TODO: error handling
//     // char numa_buf[BUF_SIZE];
//     // sprintf(numa_buf, "%d-%d", numa_start, numa_end);
//     // size_t len = strlen(numa_buf);
//     // ssize_t ret = write(fd, numa_buf, len);
//     // if (ret != len) {
//     //     fprintf(stderr, "write numa id %s to %s returns %ld, expected %ld\n", numa_buf, path_buf, ret, len);
//     //     close(fd);
//     //     return -1;
//     // }

//     close(fd);
//     return 0;
// }

// allow the process to run on cpu(s)
// int set_cpu_number_cpuset(char* cpuset_root, int cpu_start, int cpu_end) {
//     char path_buf[BUF_SIZE];
//     sprintf(path_buf, "%s%s", cpuset_root, "/cpuset.cpus");

//     // the following code does these things:
//     // echo 0-0 > /sys/fs/cgroup/.../cpuset.cpus # process is allowed to run on cpu 0
//     // echo 0-1 > /sys/fs/cgroup/.../cpuset.cpus # process is allowed to run on cpu 0 and 1
//     int fd = open(path_buf, O_WRONLY);
//     if (fd < 0) {
//         perror("open");
//         return -1;
//     }

//     // TODO: how to choose the cpu?
//     // // TODO: error handling
//     // char cpuset_buf[BUF_SIZE];
//     // sprintf(cpuset_buf, "%d-%d", cpu_start, cpu_end);
//     // size_t len = strlen(cpuset_buf);
//     // ssize_t ret = write(fd, cpuset_buf, len);
//     // if (ret != len) {
//     //     fprintf(stderr, "write cpu id %s to %s returns %ld, expected %ld\n", cpuset_buf, path_buf, ret, len);
//     //     close(fd);
//     //     return -1;
//     // }

//     close(fd);
//     return 0;
// }

// set cpuset parameters (cpu count and numa node count)
// int set_cpuset_cgroup(char* name, int cpu_start, int cpu_end, int numa_start, int numa_end) {
//     char cpuset_root[BUF_SIZE];
//     int ret;
//     sprintf(cpuset_root, cpuset_cgroup_directory_prefix, name);

//     if (cpu_start < 0 || cpu_end < 0 || cpu_start > cpu_end) {
//         cpu_start = 0;
//         cpu_end = DEFAULT_CPU_COUNT-1;
//     }

//     if (numa_start < 0 || numa_end < 0 || numa_end > numa_start) {
//         numa_start = 0;
//         numa_end = DEFAULT_NUMA_COUNT-1;
//     }

//     ret = set_cpu_number_cpuset(cpuset_root, cpu_start, cpu_end);
//     if (ret < 0)
//         return ret;
    
//     ret = set_numa_cpuset(cpuset_root, numa_start, numa_end);
//     if (ret < 0)
//         return ret;

//     return 0;
// }

// a wrapper to write the memory parameter the memory cgroupfs
// int write_memory_limit(char* memory_cgroup_root, long memory_in_bytes) {
//     char buf[BUF_SIZE];
//     char path_buf[BUF_SIZE];
//     size_t len;

//     sprintf(buf, "%ld", memory_in_bytes);
//     len = strlen(buf);

//     sprintf(path_buf, "%s%s", memory_cgroup_root, "/memory.limit_in_bytes");

//     // the following code does these things:
//     // echo 134217728 > /sys/fs/cgroup/.../memory.limit_in_bytes # process is allowed to use 128MB memory
//     int fd = open(path_buf, O_WRONLY);
//     if (fd < 0) {
//         perror("open");
//         return -1;
//     }

//     ssize_t ret = write(fd, buf, len);
//     if (ret != len) {
//         fprintf(stderr, "write memory limit %s to %s returns %ld, expected %ld\n", buf, path_buf, ret, len);
//         close(fd);
//         return -1;
//     }

//     close(fd);
//     return 0;
    
// }

// set the memory paramter for the corresponding container template
// int set_memory_cgroup(char* name, long memory_in_mb) {
//     if (memory_in_mb <= 0) {
//         // the default memory setting is the whole available memory
//         return 0;
//     }

//     char memory_cgroup_path[BUF_SIZE];
//     sprintf(memory_cgroup_path, memory_cgroup_directory_prefix, name);

//     long memory_in_bytes = memory_in_mb * 1024 * 1024;
//     return write_memory_limit(memory_cgroup_path, memory_in_bytes);
// }

// void unshare_and_fork(int* pipefd, char* rootfs) {
//     // close the read end of pipe
//     close(pipefd[0]);
//     pid_t pid = -1;
//     int ret;

//     if (rootfs) {
//         ret = chroot(rootfs);
//         if (ret < 0) {
//             perror("chroot");
//             return;
//         }
//     }

//     if (unshare(CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWIPC) < 0) {
//         perror("unshare");
//         goto end;
//     }

//     pid = fork();
//     if (pid < 0) {
//         perror("fork");
//         goto end;
//     }

//     if (pid) {
//         goto end;
//     } else {
//         close(pipefd[1]);
//         if (rootfs) {
//             ret = mount("proc", "/proc", "proc", 0, NULL);
//             if (ret < 0) {
//                 perror("mount");
//             }
//         }
//         while (1) {
//             pause();
//         }
//     }
// end:
//     write(pipefd[1], &pid, sizeof(pid));
//     close(pipefd[1]);
//     _exit(0);
// }

// ============================== end utility functions ==============================

// int setup_cached_namespace(char* rootfs) {
//     pid_t pid;
//     int pipefd[2];

//     if (pipe(pipefd) < 0) {
//         perror("pipe");
//         return -1;
//     }

//     pid = fork();
//     if (pid) {
//         // grand-parent waits for the pid from the parent process
//         // close the write end of pipe
//         pid_t target;
//         close(pipefd[1]);
//         read(pipefd[0], &target, sizeof(target));
//         waitpid(pid, NULL, 0);
//         close(pipefd[0]);
//         return target;
//     } else {
//         // parent calls unshare and forks a child
//         // write the child pid to the parent process's pipe
//         unshare_and_fork(pipefd, rootfs);
//         // should never reach here
//         assert(0);
//     }
// }

// int remove_cached_namespace(int _namespace, char* rootfs) {
//     if (rootfs) {
//         char buf[BUF_SIZE];
//         sprintf(buf, "%s%s", rootfs, "/proc");
//         int ret = umount2(buf, 0);
//         if (ret < 0) {
//             perror("umount2");
//         }
//     }
//     return kill(_namespace, SIGKILL);
// }

// int deinit_cgroup() {
//     int ret;
//     char buf[BUF_SIZE];
//     for (char** cgroup = cgroup_directory_prefix; *cgroup != NULL; cgroup++) {
//         sprintf(buf, *cgroup, "");
//         ret = rmdir(buf);
//         if (ret < 0 && errno != ENOENT) {
//             perror("rmdir");
//             return -1;
//         }
//     }
//     return 0;
// }

// int add_lean_container_template(char* name, struct ContainerSpec* spec) {
//     char buf[BUF_SIZE];
//     int ret;

//     for (char** cgroup = cgroup_directory_prefix; *cgroup != NULL; cgroup++) {
//         sprintf(buf, *cgroup, name);
//         ret = mkdir(buf, DEFAULT_PERMISSION);
//         if (ret < 0 && errno != EEXIST) {
//             perror("mkdir");
//             return -1;
//         }
//     }

//     set_cpuset_cgroup(name, spec->cpu_start, spec->cpu_end, spec->numa_start, spec->numa_end);
//     set_memory_cgroup(name, spec->memory_in_mb);
//     return 0;
// }

// int remove_lean_container_template(char* name) {
//     char buf[BUF_SIZE];
//     int ret;
//     for (char** cgroup = cgroup_directory_prefix; *cgroup != NULL; cgroup++) {
//         sprintf(buf, *cgroup, name);
//         ret = rmdir(buf);
//         if (ret < 0 && errno != ENOENT) {
//             perror("rmdir");
//             return -1;
//         }
//     }
//     return 0;
// }

int setup_lean_container(char* name, char* rootfs_path, int _namespace) {
    int ret;
    int pipefd[2];
    pid_t pid;

    if (pipe(pipefd) < 0) {
        perror("pipe");
        return -1;
    }

    if (_namespace < 0) {
        if (unshare(CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWIPC) < 0) {
            perror("unshare");
            goto err;
        }
    } else {
        // if (set_namespace(_namespace) < 0) {
        //     goto err;
        // }
        goto err;
    }
    
    pid = fork();
    if (pid < 0) {
        perror("fork");
        goto err;
    }

    if (pid) {
        // parent process
        // write the child pid to the cgroupfs
        char sign = 'a';
        char path_buf[BUF_SIZE];
        for (char** cgroup = cgroup_directory_prefix; *cgroup != NULL; cgroup++) {
            cgroup_file_name(path_buf, *cgroup, name);
            ret = write_pid(pid, path_buf);
            if (ret < 0) {
                goto err;
            }
        }
        
        // write a sign to the pipe fd to inform the child process to run
        // the child process must not run before the cgroup has been setup
        write(pipefd[1], &sign, sizeof(sign));
        close(pipefd[0]);
        close(pipefd[1]);
        return pid;
    } else {
        // child process must wait for the parent to setup cgroup
        char sign;
        int ret;

        // we first change directory to the target path and then chroot to "."
        ret = chdir(rootfs_path);
        if (ret != 0) {
            fprintf(stderr, "chdir to %s failed\n", rootfs_path);
            perror("chdir");
            goto err;
        }

        ret = chroot(".");
        if (ret != 0) {
            fprintf(stderr, "chroot failed\n");
            goto err;
        }

        ret = mount("proc", "/proc", "proc", 0, NULL);
        if (ret < 0) {
            perror("mount");
        }

        read(pipefd[0], &sign, sizeof(sign));
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }

err:
    close(pipefd[0]);
    close(pipefd[1]);
    return -1;
}

int setup_lean_container_w_double_fork(char* name, char* rootfs_path, int _namespace) {
    pid_t pid;
    int pipefd[2];

    if (pipe(pipefd) < 0) {
        perror("pipe");
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid) {
        pid_t child;
        read(pipefd[0], &child, sizeof(child));
        pid_t ret = waitpid(pid, NULL, 0);
        if (ret != pid) {
            perror("waitpid");
            return -1;
        }
        close(pipefd[0]);
        close(pipefd[1]);
        return child;
    } else {
        // close the read end of the pipe
        close(pipefd[0]);

        // setup lean container
        pid = setup_lean_container(name, rootfs_path, _namespace);
        if (pid < 0) {
            return -1;
        }

        if (pid) {
            // report the pid to the parent
            write(pipefd[1], &pid, sizeof(pid));
            close(pipefd[1]);
            _exit(0);
        } else {
            // close write end of the pipe in the containered process
            close(pipefd[1]);
            return 0;
        }
    }
}

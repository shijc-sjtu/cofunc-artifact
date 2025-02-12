#include "lean_container.h"

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#define debug(fmt, ...)

#define MAX_COMMAND_LENGTH 256
#define MAX_ENV_VAR_COUNT 256

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s [container name] [/path/to/rootfs] [command (absolute path)] [command opts]\n", argv[0]);
        return -1;
    }

    struct timespec tp1, tp2;
    clock_gettime(CLOCK_REALTIME, &tp1);
    
    char* name = argv[1];
    // char* name = "shared";
    char* rootfs_path = argv[2];
    char* command = argv[3];
    char* execve_argv[MAX_COMMAND_LENGTH];
    char* execve_envp[MAX_ENV_VAR_COUNT];
    int argv_index = 0;

    // setup argv array
    for (int i = 3; i < argc && argv_index < MAX_COMMAND_LENGTH; i++, argv_index++)
        execve_argv[argv_index] = argv[i];
    execve_argv[argv_index] = NULL;

    // setup envp array
    // TODO: support more environment variables
    execve_envp[0] = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    execve_envp[1] = NULL;

    // struct ContainerSpec spec;
    int ret;
    pid_t pid;
    
    // unlimited resources
    // spec.cpu_start = -1;
    // spec.cpu_end = -1;
    // spec.memory_in_mb = -1;
    // spec.numa_start = -1;
    // spec.numa_end = -1;

    ret = prctl(PR_SET_CHILD_SUBREAPER);
    assert(ret == 0);

    // ret = add_lean_container_template(name, &spec);
    // assert(ret == 0);

    // setup the lean container of `name`
    // and the rootfs of the lean container is specified by second parameter
    pid = setup_lean_container_w_double_fork(name, rootfs_path, -1);
    if (pid < 0) {
        printf("set lean container failed!\n");
        goto clean;
    }

    if (pid) {
        debug("this is the lean container launcher process!\n");
    } else {
        pid = getpid();
        debug("this is the process in the lean container, pid in container: %d\n", pid);

        // we are now running in the lean container!
        // launch the command by execve
        execve(command, execve_argv, execve_envp);

        // should never reach here
        assert(0);
    }

    pid_t child = waitpid(pid, NULL, 0);
    if (child != pid) {
        printf("child pid: %d, expected: %d\n", child, pid);
    }

    printf("t_launch_begin %f\n", tp1.tv_sec + tp1.tv_nsec / 1000000000.0);

clean:
    // ret = remove_lean_container_template(name);
    // assert(ret == 0);

    return 0;
}

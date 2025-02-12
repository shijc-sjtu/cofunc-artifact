#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>

double get_timestamp(void)
{
    struct timespec tp;

    clock_gettime(CLOCK_REALTIME, &tp);

    return tp.tv_sec + tp.tv_nsec / 1000000000.0;
}

int main(int argc, char *argv[])
{
    // double t_import_done;
    // double t_func_done;

    // syscall(0x1001, "import_done");
    // t_import_done = get_timestamp();

    // t_func_done = get_timestamp();
    // syscall(0x1001, "func_done");

    // printf("t_import_done %f\n", t_import_done);
    // printf("t_func_done %f\n", t_func_done);

    printf("t_end %f\n", get_timestamp());

    syscall(0x1005);

    return 0;
}

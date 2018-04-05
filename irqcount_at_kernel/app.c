
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "irqcount_ioctl.h"

#define DEVFILE "/dev/irqcount0"

void print(int fd){
    struct ioctl_cmd cmd;
    int ret;
    memset(&cmd, 0, sizeof(cmd));
    ret = ioctl(fd, IOCTL_VALGET, &cmd);
    if (ret == -1) {
        printf("errno %d\n", errno);
        perror("ioctl");
    }
    printf("val %d\n", cmd.val);
}

void set(int fd, int val){
    struct ioctl_cmd cmd;
    int ret;
    memset(&cmd, 0, sizeof(cmd));
    cmd.val = val;
    ret = ioctl(fd, IOCTL_VALSET, &cmd);
    if (ret == -1) {
        printf("errno %d\n", errno);
        perror("ioctl");
    }
}

int main(void)
{
    fork();
    fork();

    int fd;
    fd = open(DEVFILE, O_RDWR);
    if (fd == -1) {
        perror("open");
        exit(1);
    }

    print(fd);
    sleep(5);
    print(fd);
    set(fd, 777);
    print(fd);

    close(fd);

    return 0;
}


#!/bin/bash

set -e

fn_name=$(basename $(pwd))
command=$(cat command)
host_ip=${HOST_IP:-192.168.12.125}

clean() {
    until [[ -z $(mount | grep /mnt) ]]; do
        sudo umount /mnt
    done

    rm -rf .fc-rootfs
    mkdir .fc-rootfs
}

build() {
    rootfs=.fc-rootfs/rootfs.ext4

    fallocate -l 1G $rootfs
    mkfs.ext4 $rootfs

    sudo mount $rootfs /mnt

    docker rm -f $fn_name &>/dev/null || true
    docker create --name $fn_name $fn_name
    docker export $fn_name | sudo tar -C /mnt -xf -
    docker rm -f $fn_name

    ag -l "127.0.0.1" /mnt/func | sudo xargs perl -pi -E "s/127.0.0.1/$host_ip/g"

    init=/mnt/bin/myinit
    echo "#!/bin/sh" | sudo tee $init
    echo "mount -t sysfs sysfs /sys" | sudo tee -a $init
    echo "mount -t proc proc /proc" | sudo tee -a $init
    echo "mount -t tmpfs tmpfs /tmp" | sudo tee -a $init
    echo "ip addr add dev eth0 \${myip}" | sudo tee -a $init
    echo "ip link set eth0 up" | sudo tee -a $init
    echo "printf \"t_import_begin %s\\n\" \$(date +%s.%7N)" | sudo tee -a $init
    echo "$command" | sudo tee -a $init
    sudo chmod +x $init

    sudo umount /mnt
}

clean

if [[ $1 == "clean" ]]; then
    exit 0
fi

build

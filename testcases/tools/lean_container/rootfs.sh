#!/bin/bash

set -e

fn_name=$(basename $(pwd))
image_path=.rootfs/$fn_name
n=${1:-1}

prepare_image() {
        if [[ -d $image_path ]]; then
                exit 1
        fi

        mkdir -p $image_path
        docker rm -f $fn_name &>/dev/null || true
        docker create --name $fn_name $fn_name
        docker export $fn_name | tar -C $image_path -xf -
        docker rm -f $fn_name
}

prepare_rootfs() {
        if [[ ! -d $image_path ]]; then
                exit 1
        fi

        mkdir ${image_path}_$1
        sudo mount --bind $image_path ${image_path}_$1
        sudo mount --bind /dev ${image_path}_$1/dev
        sudo mount --bind /dev/hugepages ${image_path}_$1/dev/hugepages
        sudo mount -t tmpfs tmpfs ${image_path}_$1/tmp
}

prepare_rootfs_zygote() {
        prepare_rootfs zygote
        mkdir ${image_path}_zygote/root/.rootfs
        mkdir -p ${image_path}_zygote/sys/fs/cgroup
        sudo mount -t cgroup2 none ${image_path}_zygote/sys/fs/cgroup
        sudo mount --bind .rootfs ${image_path}_zygote/root/.rootfs
}

umount_all() {
        until [[ -z $(mount | grep $1) ]]; do
                sudo pkill --signal SIGUSR1 sc-runtime || true
                sudo umount $1 &>/dev/null || true
        done
}

clean_all() {
        if [[ ! -d .rootfs ]]; then
                return
        fi

        for dir in .rootfs/*; do
                if [[ $dir != $image_path ]]; then
                        # sudo umount $dir/tmp &>/dev/null || true
                        # sudo umount $dir/dev/hugepages &>/dev/null || true
                        # sudo umount $dir/dev &>/dev/null || true
                        # sudo umount $dir/proc &>/dev/null || true
                        # sudo umount $dir/root/.rootfs &>/dev/null || true
                        # sudo umount $dir/sys/fs/cgroup &>/dev/null || true
                        # [[ -z $(mount | grep $dir) ]] || sudo umount $dir
                        umount_all $dir/tmp
                        umount_all $dir/dev/hugepages
                        umount_all $dir/dev
                        umount_all $dir/proc
                        umount_all $dir/root/.rootfs
                        umount_all $dir/sys/fs/cgroup
                        [[ -z $(mount | grep $dir) ]] || sudo umount $dir
                fi
        done

        sudo rm -rf .rootfs
}

clean_all

if [[ $1 == "clean" ]]; then
        exit 0
fi

prepare_image

prepare_rootfs_zygote
for i in $(seq $n); do
        prepare_rootfs $i
done

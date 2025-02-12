#!/bin/bash

set -e

fn_name=$(basename $(pwd))
memory=$(cat memory)
n=1
hugepages=$(bc <<< "$memory/2*$n")
hp_root=/dev/hugepages/split_container

sudo mkdir -p $hp_root

clean() {
        for file in $hp_root/*; do
                sudo rm -f $file
        done
        echo 0 | sudo tee /proc/sys/vm/nr_hugepages
}

clean

if [[ $1 == "clean" ]]; then
        exit 0
fi

echo always | sudo tee /sys/kernel/mm/transparent_hugepage/shmem_enabled

echo $hugepages | sudo tee /proc/sys/vm/nr_hugepages
for i in $(seq $n); do
        sudo fallocate -l ${memory}M $hp_root/${fn_name}_$i
done

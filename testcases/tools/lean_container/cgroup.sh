#!/bin/bash

set -e

fn_name=$(basename $(pwd))
cgroup_path=/sys/fs/cgroup/split_container
n=${1:-1}

clean_all() {
        for dir in $cgroup_path/*; do
                if [[ ! -d $dir ]]; then
                        continue
                fi
                if [[ $dir =~ $cgroup_path/$fn_name* ]]; then
                        sudo rmdir $dir
                fi
        done
}

prepare_cgroup() {
        path=/sys/fs/cgroup/split_container/${fn_name}_$1
        sudo mkdir -p $path
        echo "+cpuset +cpu +io +memory +pids" | sudo tee $path/../cgroup.subtree_control &>/dev/null
        echo "0" | sudo tee $path/cpuset.cpus &>/dev/null
}

clean_all

if [[ $1 == "clean" ]]; then
        exit 0
fi

prepare_cgroup zygote
for i in $(seq $n); do
        prepare_cgroup $i
done



#!/bin/bash

set -e

fn_name=$1
times=$2

tools=$(dirname $(realpath $0))/../..

pushd $tools/../$fn_name

mkdir -p results/sev/new

if [[ -f prepare.py ]]; then
        ./prepare.py
fi

# $tools/lean_container/rootfs.sh
# $tools/lean_container/cgroup.sh
# $tools/hugepage.sh

# memory=$(cat memory)
# echo 1024 > memory
# sudo $tools/lean_container/start.sh sc-launch results/sev/new/log_sc_launch $times
# echo $memory > memory

PREALLOC=1 $tools/start.sh sc results/sev/new/log_sc_launch $times

# $tools/lean_container/rootfs.sh clean
# $tools/lean_container/cgroup.sh clean
# $tools/hugepage.sh clean

popd

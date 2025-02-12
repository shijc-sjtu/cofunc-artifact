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

$tools/start.sh linux-fork results/sev/new/log_linux_fork $times

# $tools/lean_container/rootfs.sh clean
# $tools/lean_container/cgroup.sh clean

popd

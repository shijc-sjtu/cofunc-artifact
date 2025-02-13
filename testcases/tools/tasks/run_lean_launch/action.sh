#!/bin/bash -e

fn_name=$1
times=$2

tools=$(dirname $(realpath $0))/../..

log_dir=${LOG_DIR:-/tmp/log}/$fn_name
log_file=$log_dir/lean_launch.log

pushd $tools/../testcases/$fn_name

mkdir -p $log_dir
rm -f $log_file

if [[ -f prepare.py ]]; then
        ./prepare.py
fi

$tools/lean_container/rootfs.sh
$tools/lean_container/cgroup.sh

sudo $tools/lean_container/start.sh launch $log_file $times

$tools/lean_container/rootfs.sh clean
$tools/lean_container/cgroup.sh clean

popd

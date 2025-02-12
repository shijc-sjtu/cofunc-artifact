#!/bin/bash -e

fn_name=$1
times=$2
log_dir=${LOG_DIR:-/tmp/log}/$fn_name
log_file=$log_dir/kata_launch.log

tools=$(dirname $(realpath $0))/../..

pushd $tools/../testcases/$fn_name

mkdir -p $log_dir
rm -f $log_file

if [[ -f prepare.py ]]; then
        ./prepare.py
fi

$tools/severifast/rootfs.sh
$tools/severifast/config.sh

sudo $tools/severifast/start.sh launch $log_file $times

$tools/severifast/rootfs.sh clean
$tools/severifast/config.sh clean

popd

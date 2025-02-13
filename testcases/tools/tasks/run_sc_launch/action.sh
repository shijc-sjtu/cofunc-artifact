#!/bin/bash

set -e

fn_name=$1
times=$2
log_dir=${LOG_DIR:-/tmp/log}/$fn_name
log_file=$log_dir/sc_launch.log

tools=$(dirname $(realpath $0))/../..

pushd $tools/../testcases/$fn_name

mkdir -p $log_dir
rm -f $log_file

if [[ -f prepare.py ]]; then
        ./prepare.py
fi

$tools/start.sh sc $log_file $times

popd

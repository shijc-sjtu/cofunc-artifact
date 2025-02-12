#!/bin/bash

set -e

fn_name=$1

tools=$(dirname $(realpath $0))/../..

pushd $tools/../testcases/$fn_name
$tools/lean_container/rootfs.sh clean
$tools/severifast/rootfs.sh clean
$tools/build.sh
popd

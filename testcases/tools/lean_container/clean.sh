#!/bin/bash

set -e

tools=$(dirname $0)/..

$tools/lean_container/rootfs.sh clean
$tools/lean_container/cgroup.sh clean

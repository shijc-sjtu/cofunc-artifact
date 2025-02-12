#!/bin/bash

set -e

tools=$(dirname $0)/..

$tools/lean_container/rootfs.sh
$tools/lean_container/cgroup.sh
# $tools/hugepage.sh

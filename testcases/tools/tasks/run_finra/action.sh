#!/bin/bash -e

tools=$(dirname $(realpath $0))/../..
finra=$tools/../testcases/chain_py_finra
fs=fn_py_finra_fetch_slow
ff=fn_py_finra_fetch_fast
as=fn_py_finra_audit_slow
af=fn_py_finra_audit_fast
log_dir=${LOG_DIR:-/tmp/log}

clean_cvm() {
    last=$(bc <<< "$1-1")
    for i in $(seq 0 $last); do
        SLOT_ID=$i $tools/cvm.sh clean
    done
}

prepare_cvm() {
    clean_cvm

    echo "Waiting CVMs ..."
    last=$(bc <<< "$1-1")
    for i in $(seq 0 $last); do
        SLOT_ID=$i $tools/cvm.sh &
    done
    wait
    echo "Done"
}

clean_sc_snapshot() {
    last=$(bc <<< "$1-1")
    for i in $(seq 0 $last); do
        SLOT_ID=$i $tools/sc-snapshot.sh clean
    done
}

prepare_sc_snapshot() {
    clean_sc_snapshot

    last=$(bc <<< "$1-1")
    for i in $(seq 0 $last); do
        SLOT_ID=$i $tools/sc-snapshot.sh
    done
}

run_lean_fork_fetch_slow() {
    pushd $fs
    sudo $tools/lean_container/start.sh fork results/sev/new/log_lean_fork $1
    popd
}

run_lean_fork_audit_slow() {
    pushd $as
    $tools/parallel.sh linux-fork $2 results/sev/new/log_lean_fork_$2 $1
    popd
}

run_sc_fork_fetch_fast() {
    sudo rm -f $log_dir/chain_py_finra/$ff/sc_fork.log
    pushd $ff
    prepare_cvm 1
    prepare_sc_snapshot 1
    sudo $tools/lean_container/start.sh sc-fork $log_dir/chain_py_finra/$ff/sc_fork.log $1
    clean_sc_snapshot 1
    clean_cvm 1
    popd
}

run_sc_fork_audit_fast_prepare() {
    pushd $af
    prepare_cvm $1
    prepare_sc_snapshot $1
    popd
}

run_sc_fork_audit_fast_done() {
    pushd $af
    clean_sc_snapshot $1
    clean_cvm $1
    popd
}

run_sc_fork_audit_fast() {
    sudo rm -f $log_dir/chain_py_finra/$af/sc_fork_$2.log
    pushd $af
    SLOT_NUM=$3 $tools/parallel.sh sc-restore $2 $log_dir/chain_py_finra/$af/sc_fork_$2.log $1
    popd
}

run_sc_fork_fetch_slow() {
    pushd $fs
    prepare_cvm 1
    prepare_sc_snapshot 1
    sudo $tools/lean_container/start.sh sc-fork results/sev/new/log_sc_fork $1
    clean_sc_snapshot 1
    clean_cvm 1
    popd
}

run_sc_fork_audit_slow_prepare() {
    pushd $as
    prepare_cvm $1
    prepare_sc_snapshot $1
    popd
}

run_sc_fork_audit_slow_done() {
    pushd $as
    clean_sc_snapshot $1
    clean_cvm $1
    popd
}

run_sc_fork_audit_slow() {
    pushd $as
    SLOT_NUM=$3 $tools/parallel.sh sc-restore $2 results/sev/new/log_sc_fork_$2 $1
    popd
}

run_kata_launch_fetch_slow() {
    sudo rm -f $log_dir/chain_py_finra/$fs/kata_launch.log
    pushd $fs
    $tools/severifast/config.sh
    $tools/severifast/rootfs.sh
    sudo $tools/severifast/start.sh launch $log_dir/chain_py_finra/$fs/kata_launch.log $1
    $tools/severifast/config.sh clean
    $tools/severifast/rootfs.sh clean
    popd
}

run_kata_launch_audit_slow() {
    log_file=$log_dir/chain_py_finra/$as/kata_launch_$2.log
    sudo rm -f $log_file
    pushd $as
    $tools/severifast/config_multiple.sh $2
    $tools/severifast/rootfs.sh
    until [[ -f $log_file ]]; do
        sudo $tools/severifast/parallel.sh $2 $log_file $1
    done
    $tools/severifast/config_multiple.sh clean
    $tools/severifast/rootfs.sh clean
    popd
}

pushd $finra

if [[ $1 =~ "fetch_slow" ]]; then
    pushd $fs
    ./prepare.py
    $tools/lean_container/rootfs.sh
    $tools/lean_container/cgroup.sh
    popd
fi

if [[ $1 =~ "fetch_fast" ]]; then
    pushd $ff
    $tools/lean_container/rootfs.sh
    $tools/lean_container/cgroup.sh
    popd
fi

pushd $as
./prepare.py
popd

mkdir -p $log_dir/chain_py_finra/$fs
mkdir -p $log_dir/chain_py_finra/$as
mkdir -p $log_dir/chain_py_finra/$ff
mkdir -p $log_dir/chain_py_finra/$af

run_$1 ${@:2}

if [[ $1 =~ "fetch_slow" ]]; then
    pushd $fs
    $tools/lean_container/rootfs.sh clean
    $tools/lean_container/cgroup.sh clean
    popd
fi

if [[ $1 =~ "fetch_fast" ]]; then
    pushd $ff
    $tools/lean_container/rootfs.sh clean
    $tools/lean_container/cgroup.sh clean
    popd
fi

popd

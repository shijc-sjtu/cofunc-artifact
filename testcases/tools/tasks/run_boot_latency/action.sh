#!/bin/bash

set -e

runtime=$1
fn_name=$2
times=$3
cvm_num=$4
cs=${@:5}
c_max=${@: -1}

tools=$(dirname $(realpath $0))/../..
command=$(cat $tools/../$fn_name/command)
mem_size=$(cat $tools/../$fn_name/memory)

clean_cvm() {
    last=$(bc <<< "$1-1")
    for i in $(seq 0 $last); do
        SLOT_ID=$i $tools/cvm.sh clean
    done
}

prepare_cvm() {
    clean_cvm

    echo "waiting CVMs ..."

    last=$(bc <<< "$1-1")
    for i in $(seq 0 $last); do
        SLOT_ID=$i $tools/cvm.sh &
    done
    wait
}

run_lean() {
    log_file=results/sev/new/log_lean_$1
    exec_log="exec_log"

    echo "new test @ $(date)" >> $log_file

    for _ in $(seq $3); do
        echo t_begin $(date +%s.%7N) > $exec_log

        for i in $(seq $1); do
            $tools/lean_container/start_lean_container \
                ${fn_name}_$i .rootfs/${fn_name}_1 $command >> $exec_log &
        done

        until [[ $(wc -l $exec_log | cut -d' ' -f1) -gt $1 ]]; do
            echo "waiting ..."
            sleep 1
        done

        until [[ -z $(pidof $fn_name) ]]; do
            sudo pkill -9 $fn_name &>/dev/null || true
        done

        $tools/analyze.py --log $log_file
    done
}

run_sc() {
    log_file=results/sev/new/log_sc_$1
    exec_log="exec_log"

    echo "new test @ $(date)" >> $log_file

    for _ in $(seq $3); do
        slot_ids=(0)
        for i in $(seq $1); do
            slot_ids+=($(bc <<< "$i % $2"))
        done

        echo t_begin $(date +%s.%7N) > $exec_log

        for i in $(seq $1); do
            $tools/lean_container/start_lean_container \
                ${fn_name}_$i .rootfs/${fn_name}_1 /bin/sc-runtime -m xxx $mem_size --slot ${slot_ids[$i]} $command >> $exec_log &
        done

        until [[ $(wc -l $exec_log | cut -d' ' -f1) -gt $1 ]]; do
            echo "waiting ..."
            sleep 1
        done

        until [[ -z $(pidof sc-runtime) ]]; do
            sudo pkill -SIGUSR2 sc-runtime &>/dev/null || true
        done

        $tools/analyze.py --log $log_file
    done
}

pushd $tools/../$fn_name

mkdir -p results/sev/new

$tools/lean_container/rootfs.sh
$tools/lean_container/cgroup.sh $c_max

if [[ $runtime == "sc" ]]; then
    prepare_cvm $cvm_num
fi

for c in $cs; do
    run_$runtime $c $cvm_num $times
done

if [[ $runtime == "sc" ]]; then
    clean_cvm $cvm_num
fi

$tools/lean_container/rootfs.sh clean
$tools/lean_container/cgroup.sh clean

popd

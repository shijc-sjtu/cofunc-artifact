#!/bin/bash

set -e

tools=$(dirname $0)/..
concurrency=$1
result_log=$2
times=${3:-1}
exec_log="exec_log"

if [[ $result_log != "" ]]; then
        echo "new test @ $(date)" >> $result_log
fi

for _ in $(seq $times); do
    echo "" > $exec_log

    $tools/severifast/wait.py $concurrency | tee -a $exec_log &
    sleep 1


    echo t_begin $(date +%s.%7N) | tee -a $exec_log

    for i in $(seq $concurrency); do
        $tools/../severifast-assets/firecracker \
            --no-api --config-file $(pwd)/.fc-config/vm_config_$i.json --no-seccomp &>/dev/null &
    done

    wait

    if [[ $result_log != "" ]]; then
        $tools/analyze.py --log $result_log
    else
        $tools/analyze.py
    fi
done

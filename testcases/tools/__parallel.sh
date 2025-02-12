#!/bin/bash

runtime=$1; shift
count=$1; shift
command=$@
slot_num=${SLOT_NUM:-1}

export SILENT=1

/tools/wait.py $count &
sleep 1

if [[ $runtime == "runc" ]]; then
    echo t_begin $(date +%s.%7N)
    for i in $(seq $count); do
        taskset -c $i $command &
    done
elif [[ $runtime == "sc" ]]; then
    echo t_begin $(date +%s.%7N)
    for i in $(seq $count); do
        taskset -c $i /bin/sc-runtime $command &
    done
elif [[ $runtime == "linux-fork" ]]; then
    taskset -c 0 $command --linux-fork $count
elif [[ $runtime == "sc-restore" ]]; then
    slot_ids=(0)
    for i in $(seq $count); do
        slot_ids+=($(echo "${i}%${slot_num}" | bc))
    done
    cpu_num=$(nproc)
    cpus=(0)
    for i in $(seq $count); do
        cpus+=($(echo "${i}%${cpu_num}" | bc))
    done
    echo t_begin $(date +%s.%7N)
    for i in $(seq $count); do
        taskset -c ${cpus[$i]} /bin/sc-runtime --slot ${slot_ids[$i]} &
    done
else
    exit 1
fi

wait

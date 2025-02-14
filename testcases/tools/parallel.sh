#!/bin/bash

set -e

fn_name=$(basename $(pwd))
command=$(cat command)
runtime=$1
count=$2
result_log=$3
name=$fn_name
times=${4:-1}
exec_log="exec_log"
tools=$(dirname $0)
slot_num=${SLOT_NUM:-1}

# if [[ $result_log != "" ]]; then
#         echo "new test @ $(date)" >> $result_log
# fi

docker rm -f $name &>/dev/null || true

for i in $(seq $times); do
    rm -f $exec_log
    docker run -it --rm --privileged --net=host --name $name \
        -v /dev:/dev --tmpfs /tmp --tmpfs /run --env SLOT_NUM=$slot_num \
        $fn_name /tools/parallel.sh $runtime $count $command  | tee -a $exec_log

    if [[ $result_log != "" ]]; then
        $tools/analyze.py --log $result_log
    else
        $tools/analyze.py
    fi
done

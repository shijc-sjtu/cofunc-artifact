#!/bin/bash

set -e

fn_name=$(basename $(pwd))
command=$(cat command)
mem_size=$(cat memory)
shared_pool=""; [ -e small_shared_pool ] && shared_pool="--small-shared-pool"
runtime=$1
exec_log="exec_log"
result_log=$2
name=$fn_name
times=${3:-1}
tools=$(dirname $0)/..
mem_file="/dev/hugepages/split_container/${fn_name}_1"

# if [[ "$fn_name" =~ "_py_" ]]; then
#         cpu_param="--cpuset-cpus 0"
# elif [[ "$fn_name" =~ "_js_" ]]; then
#         cpu_param="--cpu-shares 1024"
# fi

if [[ $(whoami) != "root" ]]; then
        echo not run as root
        exit 1
fi

if [[ $runtime == "fork" ]]; then
        command="$command --lean-fork ${fn_name}"
        name="${fn_name}_zygote"
elif [[ $runtime == "launch" ]]; then
        command="$command"
        name="${fn_name}_1"
elif [[ $runtime == "sc-launch" ]]; then
        command="/bin/sc-runtime -m $mem_file $mem_size $shared_pool $command"
        name="${fn_name}_1"
elif [[ $runtime == "sc-fork" ]]; then
        command="/bin/sc-runtime -m $mem_file $mem_size $shared_pool"
        name="${fn_name}_1"
elif [[ $runtime == "shell" ]]; then
        command="/bin/sh"
        name="${fn_name}_1"
else
        exit 1
fi

# if [[ $result_log != "" ]]; then
#         echo "new test @ $(date)" >> $result_log
# fi

for i in $(seq $times); do
        # t_begin=$(date +%s.%7N)
        # printf "t_begin %s\n" $t_begin | tee $exec_log

        echo "mode lean-${runtime}" > $exec_log

        # docker run -it --rm --privileged --net=host $cpu_param --name $name \
        #         -v /dev:/dev --tmpfs /tmp --tmpfs /run \
        #         $fn_name /tools/start.sh $command | tee -a $exec_log

        $tools/lean_container/start_lean_container \
                $name .rootfs/$name $command | tee -a $exec_log

        if [[ $result_log != "" ]]; then
                $tools/analyze.py --log $result_log
        else
                $tools/analyze.py
        fi
done
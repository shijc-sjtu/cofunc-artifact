#!/bin/bash -e

tools=$(dirname $0)/..
runtime=$1
exec_log="exec_log"
result_log=$2
times=${3:-1}

if [[ ! $runtime == "launch" ]]; then
        exit 1
fi

# if [[ $result_log != "" ]]; then
#         echo "new test @ $(date)" >> $result_log
# fi

for i in $(seq $times); do
        echo "mode kata-${runtime}" > $exec_log

        printf "t_launch_begin %s\n" $(date +%s.%7N) | tee -a $exec_log

        sudo $tools/../severifast-assets/firecracker \
                --no-api --config-file $(pwd)/.fc-config/vm_config_1.json --no-seccomp | tee -a $exec_log

        if [[ $result_log != "" ]]; then
                $tools/analyze.py --log $result_log
        else
                $tools/analyze.py
        fi
done

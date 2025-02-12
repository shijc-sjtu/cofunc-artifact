#!/bin/bash

set -e

tools=$(dirname $0)
task=$tools/tasks/$1

if [[ -f $task/prepare.sh ]]; then
        $task/prepare.sh
fi

while read -u 10 param; do
        $task/action.sh $param
done 10<$task/params

if [[ -f $task/cleanup.sh ]]; then
        $task/cleanup.sh
fi

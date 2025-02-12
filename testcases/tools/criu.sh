#!/bin/bash

fn_name=$(basename $(pwd))
command=$(cat command)
name=$fn_name

docker run -it --privileged --cpuset-cpus 0 --tmpfs /run --name $name \
        $fn_name /tools/criu.sh $command
docker commit $name $fn_name
docker rm $name

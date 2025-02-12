#!/bin/sh

command=$@
program=$(basename $(echo $command | cut -d' ' -f1))

rm -rf /criu
mkdir /criu
mkdir /criu/checkpoint
echo 0 > /criu/restore_flag

$command --criu-snapshot &
sleep 3

pid=$(pidof $program)
criu dump -t $pid -D /criu/checkpoint -j

echo 1 > /criu/restore_flag

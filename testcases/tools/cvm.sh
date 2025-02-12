#!/bin/bash -e

cvm_path=$(dirname $0)/../../cvm_os
slot_id=${SLOT_ID:-0}
session=split-container-cvm-${slot_id}

clean() {
        until [[ -z $(pidof qemu-system-x86_64) ]]; do
                sudo pkill -9 qemu &>/dev/null || true
        done
        sudo screen -X -S $session quit &>/dev/null || true
}

if [[ $1 == "clean" ]]; then
        clean
        exit 0
fi

if [[ -z $SLOT_ID ]]; then
        clean
fi

pushd $cvm_path

sudo rm exec_log_$slot_id &>/dev/null || true
touch exec_log_$slot_id

sudo SLOT_ID=$slot_id screen -dmS $session build/simulate.sh

until [[ ! -z $(cat exec_log_$slot_id | grep "ChCore shell") ]]; do
        sleep 1
done

popd

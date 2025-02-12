#!/bin/bash

fn_name=$(basename $(pwd))
slot_id=${SLOT_ID:-0}

if [[ $1 == "snapshot" ]]; then
        name="$fn_name"_snapshot_"$slot_id"
else
        name=$fn_name
fi

docker exec $name pkill -USR1 sc-runtime

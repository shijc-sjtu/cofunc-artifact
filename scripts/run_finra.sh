#!/bin/bash

export HOST_IP=$(jq -r ".host_ip" config.json)
export CNTR_IP=$(jq -r ".cntr_ip" config.json)
export LOG_DIR="$(pwd)/log"

testcases/tools/run_task.sh run_finra

scripts/plot_finra.py

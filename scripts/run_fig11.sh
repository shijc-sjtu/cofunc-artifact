#!/bin/bash -e

export CNTR_IP=$(jq -r ".cntr_ip" config.json)
export HOST_IP=$(jq -r ".host_ip" config.json)
export LOG_DIR="$(pwd)/log"

# Run CoFunc
testcases/tools/run_task.sh run_sc_fork
testcases/tools/run_task.sh run_sc_launch # Emulate the measurement/encryption overhead for Kata-CVM

# Run Kata-CVM baseline (with SEVeriFast optimization)
testcases/tools/run_task.sh run_severifast_launch

# Run Native baseline
testcases/tools/run_task.sh run_lean_fork
testcases/tools/run_task.sh run_lean_launch # Multi-threading fork is not supported for Native
pushd testcases/testcases/microbenchmarks/cow; ./eval.py $LOG_DIR/microbenchmarks/cow/result; popd

# Generate table and figure
scripts/plot_fig11.py

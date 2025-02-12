#!/bin/bash -e

GREEN='\033[0;32m'
NONE='\033[0m'

echo_info() {
    echo -e "${GREEN}$@${NONE}"
}

echo_info "Start platform servers ..."
testcases/environment/start_all.sh

echo_info "Start CVM ..."
testcases/tools/cvm.sh

echo_info "Run the face detection function"
pushd testcases/testcases/fn_py_face_detection
./prepare.py
../../tools/start.sh sc
popd

echo_info "Shutdown CVM ..."
testcases/tools/cvm.sh clean

echo_info "Shutdown platform servers ..."
testcases/environment/shutdown_all.sh

echo_info "Done"

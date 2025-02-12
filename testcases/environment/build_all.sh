#!/bin/bash -e

pushd device && ./build.sh && popd
pushd file_server && ./build.sh && popd
pushd parameter && ./build.sh && popd

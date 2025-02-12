#!/bin/bash -e

# Build QEMU

rm -rf qemu
git clone -b svsm-preview-v2 --depth=1 https://github.com/AMDESE/qemu.git

pushd qemu

git checkout 2c6dbe30d
git apply ../patches/qemu.patch

mkdir build && cd build
../configure --target-list=x86_64-softmmu
make -j$(nproc)

popd

# Build CVM OS

pushd cvm_os
sudo rm -rf build
./download_musl.sh
./chbuild build
popd

# Build shadow container code

pushd shadow_container
./build.sh
popd

# Build platform servers

pushd testcases/environment
./build_all.sh
popd

# Build container images

pushd testcases/tools/js_binding; ./build.sh; popd
pushd testcases/tools/libc_builder; ./build.sh; popd
./testcases/tools/run_task.sh build

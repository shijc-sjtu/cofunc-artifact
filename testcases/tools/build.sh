#!/bin/bash

set -e

fn_name=$(basename $(pwd))
base_name="$fn_name"_base
tools=$(dirname $0)

cp -r $tools tools
docker build -t $base_name .
docker build -t $fn_name -f tools/Dockerfile --build-arg BASE_NAME=$base_name .
rm -r tools

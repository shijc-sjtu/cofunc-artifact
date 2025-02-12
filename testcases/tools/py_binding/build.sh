#!/bin/sh

set -e

if ! command -v python &> /dev/null
then
    exit 0
fi

apk add build-base
apk add python3-dev
python setup.py install
# docker build -t sc_py_binding_builder .

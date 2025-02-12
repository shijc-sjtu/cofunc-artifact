#!/bin/bash

set -e

tools=$(dirname $(realpath $0))/../..

$tools/cvm.sh clean

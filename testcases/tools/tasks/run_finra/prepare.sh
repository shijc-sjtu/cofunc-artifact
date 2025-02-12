#!/bin/bash

set -e

tools=$(dirname $(realpath $0))/../..

$tools/../environment/start_all.sh

#!/bin/bash

set -e

tools=$(dirname $(realpath $0))/../..

$tools/../environment/shutdown_all.sh
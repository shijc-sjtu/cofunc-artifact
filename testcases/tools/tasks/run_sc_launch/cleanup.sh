#!/bin/bash

tools=$(dirname $(realpath $0))/../..

$tools/../environment/shutdown_all.sh
$tools/cvm.sh clean
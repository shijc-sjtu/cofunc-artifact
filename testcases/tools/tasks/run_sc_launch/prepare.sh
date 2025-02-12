#!/bin/bash

tools=$(dirname $(realpath $0))/../..

$tools/../environment/start_all.sh
$tools/cvm.sh

#!/bin/sh

t_begin=$(date +%s.%7N)
printf "t_runc_init %s\n" $t_begin

$@

#!/bin/bash

fn_name=$(basename $(pwd))

docker pull billsjcdocker/$fn_name:latest
docker tag billsjcdocker/$fn_name:latest $fn_name

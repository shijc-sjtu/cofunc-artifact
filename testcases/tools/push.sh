#!/bin/bash

fn_name=$(basename $(pwd))

docker tag $fn_name billsjcdocker/$fn_name:latest
docker push billsjcdocker/$fn_name:latest

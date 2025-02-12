#!/bin/bash

docker run -it --rm --name scenv_param --net=host -v $(dirname $0)/../..:/testcases scenv_param

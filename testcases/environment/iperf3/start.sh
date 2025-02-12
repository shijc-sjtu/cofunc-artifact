#!/bin/bash

docker run -it --rm --net=host iperf3 iperf3 -s -A 4

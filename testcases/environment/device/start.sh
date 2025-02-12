#!/bin/bash

docker run -it --rm --env DEVICE_NAME=tv --name scenv_device --net=host scenv_device

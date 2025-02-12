#!/bin/bash

docker run -it --rm --name scenv_minio \
    --net=host \
    -e "MINIO_ROOT_USER=root" \
    -e "MINIO_ROOT_PASSWORD=password" \
    minio/minio server /data
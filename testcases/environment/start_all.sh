#!/bin/bash -e

$(dirname $0)/shutdown_all.sh

docker run -d --rm --name scenv_minio \
    --net=host \
    -e "MINIO_ROOT_USER=root" \
    -e "MINIO_ROOT_PASSWORD=password" \
    minio/minio server /data

docker run -d --rm --name scenv_file_server --net=host scenv_file_server

docker run -d --rm --env DEVICE_NAME=tv --name scenv_device --net=host scenv_device

docker run -d --rm --name scenv_param --net=host -v $(realpath $(dirname $0)/..):/testcases scenv_param

docker run -d --rm --name scenv_couchdb \
    --net=host \
    -e "COUCHDB_USER=admin" \
    -e "COUCHDB_PASSWORD=password" \
    couchdb

sleep 2

curl http://localhost:9090 &>/dev/null
curl http://localhost:8888 &>/dev/null

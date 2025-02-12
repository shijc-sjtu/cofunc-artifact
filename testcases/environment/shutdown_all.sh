#!/bin/bash

docker rm -f scenv_minio &>/dev/null || true

docker rm -f scenv_file_server &>/dev/null || true

docker rm -f scenv_device &>/dev/null || true

docker rm -f scenv_param &>/dev/null || true

docker rm -f scenv_couchdb &>/dev/null || true

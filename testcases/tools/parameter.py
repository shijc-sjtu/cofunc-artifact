#!/bin/python
import string

config = {
    'MINIO_IP': '127.0.0.1',
    'MINIO_PORT': '9000',
    'FILE_SERVER_IP': '127.0.0.1',
    'FILE_SERVER_PORT': '8080'
}

with open('parameter') as file:
    template = string.Template(file.read())

param = template.safe_substitute(config)

with open('__parameter', 'w') as file:
    file.write(param)

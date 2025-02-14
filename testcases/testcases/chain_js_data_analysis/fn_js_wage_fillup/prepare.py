#!/bin/python
import subprocess

while True:
    out = subprocess.check_output(["./prepare.sh"])
    if "internal_server_error" not in out.decode("utf-8"):
        break

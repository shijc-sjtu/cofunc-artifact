#!/bin/python
import subprocess
import os
import sys

output_filename = os.path.realpath(sys.argv[1])

os.environ["NO_ANALYSIS"] = "1"
command = ["../../../tools/start.sh", "linux-fork"]

N = 50
total = 0
for _ in range(N):
    total += float(subprocess.check_output(command).decode("utf-8").split()[-1])
avg = total / N

os.makedirs(os.path.dirname(output_filename), exist_ok=True)
with open(output_filename, "w") as file:
    file.write(str(avg))

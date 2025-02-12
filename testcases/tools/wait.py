#!/usr/local/bin/python
import sys
import os
import time


count = int(sys.argv[1])


os.mkfifo('/run/pipe_done')
os.mkfifo('/run/pipe_clean')


with open('/run/pipe_done', 'rb') as pipe:
    left = count
    while left:
        left -= len(pipe.read())

print(f't_end {time.time()}')

with open('/run/pipe_clean', 'wb') as pipe:
    for _ in range(count):
        pipe.write(b'1')

#!/bin/python
import sys, time, os
from flask import Flask

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

n = int(sys.argv[1])

app = Flask(__name__)

@app.route('/done')
def done():
    global n
    n -= 1
    print(n, flush=True)
    if n == 0:
        print(f"t_end {time.time()}", flush=True)
        os._exit(0)
    return "OK"

app.run(host="0.0.0.0", port="9999")

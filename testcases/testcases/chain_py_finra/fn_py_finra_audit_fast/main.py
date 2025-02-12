import sys, ctypes, time, os
libc = ctypes.CDLL(None)
SYS_SC_SNAPSHOT = 0x1000

import requests
import pandas as pd
import numpy as np
import io


def fetch_data(url):
    resp = requests.get(url)
    yfinance_csv = resp.content.decode()
    return pd.read_csv(io.StringIO(yfinance_csv))


def do_audit(yfinance):
    finance_columns = ['Open', 'High', 'Low', 'Close', 'Volume', 'Dividends', 'Stock Splits']
    avg_data = [np.average(yfinance[key]) for key in finance_columns]
    sum_data = [np.sum(yfinance[key]) for key in finance_columns]
    std_data = [np.std(yfinance[key]) for key in finance_columns]
    return avg_data, sum_data, std_data


def notify_done(pipe_name):
    with open(pipe_name, 'wb') as pipe:
        pipe.write(b'1')


def wait_clean(pipe_name):
    with open(pipe_name, 'rb') as pipe:
        pipe.read(1)


yfinance = fetch_data('http://127.0.0.1:8080/yfinance.csv')

if len(sys.argv) < 2:
    pass
elif sys.argv[1] == '--sc-snapshot':
    libc.syscall(SYS_SC_SNAPSHOT)
elif sys.argv[1] == '--linux-fork':
    print(f't_begin {time.time()}')
    count = int(sys.argv[2])
    for i in range(count):
        pid = os.fork()
        if not pid:
            os.sched_setaffinity(0, {i})
            os.sched_yield()
            break
    if pid:
        for _ in range(count):
            os.wait()
            os._exit(0)


do_audit(yfinance)
notify_done('/run/pipe_done')
wait_clean('/run/pipe_clean')

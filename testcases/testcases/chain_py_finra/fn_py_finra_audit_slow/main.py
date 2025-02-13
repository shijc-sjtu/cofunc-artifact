import sys, ctypes, time, os
libc = ctypes.CDLL(None)
SYS_SC_SNAPSHOT = 0x1000

import pandas as pd
import numpy as np
import json
import boto3
from boto3.s3.transfer import TransferConfig
import urllib.parse
import urllib.request


boto3.client('s3',
    endpoint_url='http://127.0.0.1:9000',
    aws_access_key_id='root',
    aws_secret_access_key='password')


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
            os.sched_setaffinity(0, {i % 96})
            os.sched_yield()
            break
    if pid:
        for _ in range(count):
            os.wait()
            os._exit(0)


def fetch_data():
    s3_client = boto3.client('s3',
        endpoint_url='http://127.0.0.1:9000',
        aws_access_key_id='root',
        aws_secret_access_key='password')
    config = TransferConfig(use_threads=False)
    s3_client.download_file('input', 'yfinance.json', '/tmp/yfinance.json', Config=config)
    with open('/tmp/yfinance.json') as file:
        yfinance_json = file.read()
    yfinance_dict = json.loads(yfinance_json)
    yfinance = pd.DataFrame.from_dict(yfinance_dict)
    return yfinance


def do_audit(yfinance):
    finance_columns = ['Open', 'High', 'Low', 'Close', 'Volume', 'Dividends', 'Stock Splits']
    avg_data = [np.average(yfinance[key]) for key in finance_columns]
    sum_data = [np.sum(yfinance[key]) for key in finance_columns]
    std_data = [np.std(yfinance[key]) for key in finance_columns]


def notify_done_net():
    req = urllib.request.Request('http://127.0.0.1:9999/done')
    urllib.request.urlopen(req)


def notify_done(pipe_name):
    if not os.path.exists(pipe_name):
        notify_done_net()
        return
    with open(pipe_name, 'wb') as pipe:
        pipe.write(b'1')

    
def wait_clean(pipe_name):
    if not os.path.exists(pipe_name):
        return
    with open(pipe_name, 'rb') as pipe:
        pipe.read(1)


def get_param(fn_name):
    data = urllib.parse.urlencode({"fn_name": fn_name})
    data = data.encode('ascii')
    req = urllib.request.Request('http://127.0.0.1:8888/get_param', data)
    with urllib.request.urlopen(req) as resp:
        data = resp.read()
    data = data.replace(b'hostname', b'127.0.0.1')
    return json.loads(data)


def set_retval(fn_name, retval):
    data = urllib.parse.urlencode({"fn_name": fn_name, "retval": json.dumps(retval)})
    data = data.encode('ascii')
    req = urllib.request.Request('http://127.0.0.1:8888/set_retval', data)
    with urllib.request.urlopen(req) as resp:
        data = resp.read()
    assert data == b'OK'


fn_name='testcases/chain_py_finra/fn_py_finra_audit_slow'
param = get_param(fn_name)
yfinance = fetch_data()
retval = do_audit(yfinance)
set_retval(fn_name, retval)
notify_done('/run/pipe_done')
wait_clean('/run/pipe_clean')

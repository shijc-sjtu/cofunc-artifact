import pandas as pd
import numpy as np
import json
import boto3
from boto3.s3.transfer import TransferConfig
import requests
import io


def fetch_data(url):
    resp = requests.get(url)
    yfinance_csv = resp.content.decode()
    return pd.read_csv(io.StringIO(yfinance_csv))


def serialize_data(yfinance):
    yfinance_dict = yfinance.to_dict()
    return json.dumps(yfinance_dict)


def upload_data(yfinance_json):
    with open("/tmp/yfinance.json", "w") as file:
        file.write(yfinance_json)
    s3_client = boto3.client('s3',
        endpoint_url='http://127.0.0.1:9000',
        aws_access_key_id='root',
        aws_secret_access_key='password')
    config = TransferConfig(use_threads=False)
    s3_client.upload_file('/tmp/yfinance.json', 'input', 'yfinance.json', Config=config)


def handler(param):
    yfinance = fetch_data('http://127.0.0.1:8080/yfinance.csv')
    yfinance_json = serialize_data(yfinance)
    upload_data(yfinance_json)

fn_name = "testcases/chain_py_finra/fn_py_finra_fetch_slow"

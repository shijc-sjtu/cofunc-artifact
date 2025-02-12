import pandas as pd
import requests
import io


def fetch_data(url):
    resp = requests.get(url)
    yfinance_csv = resp.content.decode()
    return pd.read_csv(io.StringIO(yfinance_csv))


def handler(param):
    fetch_data('http://127.0.0.1:8080/yfinance.csv')

fn_name = "testcases/chain_py_finra/fn_py_finra_fetch_fast"

import json
from urllib.request import urlopen
import time


def lambda_handler(event, context):
    link = event['link']  # https://github.com/jdorfman/awesome-json-datasets

    f = urlopen(link)
    data = f.read().decode("utf-8")

    json_data = json.loads(data)
    str_json = json.dumps(json_data, indent=4)


def handler(param):
    lambda_handler(param, None)


fn_name = 'testcases/fn_py_json'

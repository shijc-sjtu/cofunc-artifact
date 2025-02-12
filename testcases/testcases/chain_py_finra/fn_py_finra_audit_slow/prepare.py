#!/bin/python
import os
import json
import boto3
import pandas as pd


ENDPOINT_URL = 'http://127.0.0.1:9000'
AWS_ACCESS_KEY_ID = 'root'
AWS_SECRET_ACCESS_KEY = 'password'
INPUT_BUCKET = 'input'
OUTPUT_BUCKET = 'output'
OBJECT_KEY = 'yfinance.json'


yfinance = pd.read_csv('./yfinance.csv')
yfinance_dict = yfinance.to_dict()
yfinance_json = json.dumps(yfinance_dict)

with open('yfinance.json', 'w') as file:
    file.write(yfinance_json)


s3_client = boto3.client('s3',
                    endpoint_url=ENDPOINT_URL,
                    aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

buckets = [obj['Name'] for obj in s3_client.list_buckets()['Buckets']]
if INPUT_BUCKET not in buckets:
        s3_client.create_bucket(Bucket=INPUT_BUCKET)
if OUTPUT_BUCKET not in buckets:
        s3_client.create_bucket(Bucket=OUTPUT_BUCKET)

s3_client.upload_file(OBJECT_KEY, INPUT_BUCKET, OBJECT_KEY)

os.remove('yfinance.json')

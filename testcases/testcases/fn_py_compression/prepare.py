#!/bin/python
import glob, os
import boto3


ENDPOINT_URL = 'http://127.0.0.1:9000'
AWS_ACCESS_KEY_ID = 'root'
AWS_SECRET_ACCESS_KEY = 'password'
INPUT_BUCKET = 'input'
OUTPUT_BUCKET = 'output'


s3_client = boto3.client('s3',
                    endpoint_url=ENDPOINT_URL,
                    aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY)


buckets = [obj['Name'] for obj in s3_client.list_buckets()['Buckets']]
if INPUT_BUCKET not in buckets:
        s3_client.create_bucket(Bucket=INPUT_BUCKET)
if OUTPUT_BUCKET not in buckets:
        s3_client.create_bucket(Bucket=OUTPUT_BUCKET)


def upload_files(data_root, data_dir, upload_func):
    for root, dirs, files in os.walk(data_dir):
        prefix = os.path.relpath(root, data_root)
        for file in files:
            file_name = prefix + '/' + file
            filepath = os.path.join(root, file)
            upload_func(0, file_name, filepath)


def generate_input(data_dir, size, input_buckets, output_buckets, upload_func):
    for dir in os.listdir(data_dir):
        upload_files(data_dir, os.path.join(data_dir, dir), upload_func)


def minio_upload_func(bucket_idx, key, filepath):
    s3_client.upload_file(filepath, INPUT_BUCKET, key)


generate_input('sample-data', 0, 'input', 'output', minio_upload_func)

#!/bin/python
import boto3


ENDPOINT_URL = 'http://127.0.0.1:9000'
AWS_ACCESS_KEY_ID = 'root'
AWS_SECRET_ACCESS_KEY = 'password'
OUTPUT_BUCKET = 'output'


s3_client = boto3.client('s3',
                    endpoint_url=ENDPOINT_URL,
                    aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY)


buckets = [obj['Name'] for obj in s3_client.list_buckets()['Buckets']]
if OUTPUT_BUCKET not in buckets:
        s3_client.create_bucket(Bucket=OUTPUT_BUCKET)

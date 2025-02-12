#!/bin/python
import boto3


ENDPOINT_URL = 'http://127.0.0.1:9000'
AWS_ACCESS_KEY_ID = 'root'
AWS_SECRET_ACCESS_KEY = 'password'
SRC_BUCKET = 'input'
JOB_BUCKET = 'job'
OBJECT_KEYS = [
    "C#.html",
    "C++.html",
    "Clojure.html",
    "CSS.html",
    "Groovy.html",
    "Haskell.html",
    "Java.html",
    "JavaScript.html",
    "MATLAB.html",
    "Objective-C.html",
    "Perl.html",
    "PHP.html",
    "Python.html",
    "Ruby.html",
    "Scala.html",
]


s3_client = boto3.client('s3',
                    endpoint_url=ENDPOINT_URL,
                    aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

buckets = [obj['Name'] for obj in s3_client.list_buckets()['Buckets']]
if SRC_BUCKET not in buckets:
    s3_client.create_bucket(Bucket=SRC_BUCKET)
if JOB_BUCKET not in buckets:
    s3_client.create_bucket(Bucket=JOB_BUCKET)


for key in OBJECT_KEYS:
    s3_client.upload_file(f"dataset/{key}", SRC_BUCKET, key)

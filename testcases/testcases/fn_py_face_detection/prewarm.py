import boto3
import time
from boto3.s3.transfer import TransferConfig
import uuid
import cv2

# Load boto3
boto3.client('s3',
    endpoint_url='http://127.0.0.1:9000',
    aws_access_key_id='root',
    aws_secret_access_key='password')

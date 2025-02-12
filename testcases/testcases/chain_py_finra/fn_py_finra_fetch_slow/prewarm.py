import pandas as pd
import numpy as np
import json
import boto3
from boto3.s3.transfer import TransferConfig
import requests
import io

s3_client = boto3.client('s3',
        endpoint_url='http://127.0.0.1:9000',
        aws_access_key_id='root',
        aws_secret_access_key='password')

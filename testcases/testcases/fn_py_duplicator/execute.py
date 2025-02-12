import boto3
from boto3.s3.transfer import TransferConfig

config = TransferConfig(use_threads=False)

def handler(event):
    input_bucket = event['input_bucket']
    object_key = event['object_key']
    output_bucket = event['output_bucket']
    endpoint_url = event['endpoint_url']
    aws_access_key_id = event['aws_access_key_id']
    aws_secret_access_key = event['aws_secret_access_key']

    s3_client = boto3.client('s3',
                    endpoint_url=endpoint_url,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key)

    path = '/tmp/'+object_key

    s3_client.download_file(input_bucket, object_key, path, Config=config)

    s3_client.upload_file(path, output_bucket, object_key, Config=config)


fn_name = 'testcases/fn_py_duplicator'

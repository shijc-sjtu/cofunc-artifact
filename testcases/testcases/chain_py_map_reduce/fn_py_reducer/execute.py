import json
import boto3


computer_language = ["JavaScript", "Java", "PHP", "Python", "C#", "C++",
                     "Ruby", "CSS", "Objective-C", "Perl",
                     "Scala", "Haskell", "MATLAB", "Clojure", "Groovy"]


def handler(args):
    job_bucket = args['job_bucket']
    endpoint_url = args['endpoint_url']
    aws_access_key_id = args['aws_access_key_id']
    aws_secret_access_key = args['aws_secret_access_key']

    s3 = boto3.resource('s3',
                    endpoint_url=endpoint_url,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key)
    s3_client = boto3.client('s3',
                    endpoint_url=endpoint_url,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key)

    output = {}

    for lang in computer_language:
        output[lang] = 0

    network = 0
    reduce = 0

    all_keys = []
    for obj in s3.Bucket(job_bucket).objects.all():
        all_keys.append(obj.key)

    for key in all_keys:
        response = s3_client.get_object(Bucket=job_bucket, Key=key)
        contents = response['Body'].read()

        data = json.loads(contents.decode("utf-8"))
        for key in data:
            output[key] += data[key]


fn_name = 'testcases/chain_py_map_reduce/fn_py_reducer'

import json
import boto3


# subs = "</title><text>"
computer_language = ["JavaScript", "Java", "PHP", "Python", "C#", "C++",
                     "Ruby", "CSS", "Objective-C", "Perl",
                     "Scala", "Haskell", "MATLAB", "Clojure", "Groovy"]


def handler(args):
    job_bucket = args['job_bucket']
    src_bucket = args['bucket']
    src_keys = args['keys']
    mapper_id = args['mapper_id']
    endpoint_url = args['endpoint_url']
    aws_access_key_id = args['aws_access_key_id']
    aws_secret_access_key = args['aws_secret_access_key']

    s3_client = boto3.client('s3',
                    endpoint_url=endpoint_url,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key)

    output = {}

    for lang in computer_language:
        output[lang] = 0

    keys = src_keys.split('/')

    # Download and process all keys
    for key in keys:
        response = s3_client.get_object(Bucket=src_bucket, Key=key)
        contents = response['Body'].read()

        for line in contents.decode("utf-8").split('\n'):
            # idx = line.find(subs)
            # text = line[idx + len(subs): len(line) - 16]
            text = line
            for lang in computer_language:
                if lang in text:
                    output[lang] += 1

    s3_client.put_object(Bucket=job_bucket, Key=str(mapper_id), Body=json.dumps(output))


fn_name = 'testcases/chain_py_map_reduce/fn_py_mapper'

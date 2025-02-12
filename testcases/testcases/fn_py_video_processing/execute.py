import sys, ctypes
libc = ctypes.CDLL(None)
sys.dont_write_bytecode = True


import boto3
import uuid
from boto3.s3.transfer import TransferConfig
import time
import cv2


tmp = "/tmp/"
FILE_NAME_INDEX = 0
FILE_PATH_INDEX = 2


config = TransferConfig(use_threads=False)


def video_processing(object_key, video_path):
    file_name = object_key.split(".")[FILE_NAME_INDEX]
    result_file_path = tmp+file_name+'-output.avi'

    video = cv2.VideoCapture(video_path)

    width = int(video.get(3))
    height = int(video.get(4))

    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter(result_file_path, fourcc, 20.0, (width, height))

    start = time.time()
    while video.isOpened():
        ret, frame = video.read()

        if ret:
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            tmp_file_path = tmp+'tmp.jpg'
            cv2.imwrite(tmp_file_path, gray_frame)
            gray_frame = cv2.imread(tmp_file_path)
            out.write(gray_frame)
        else:
            break

    latency = time.time() - start

    video.release()
    out.release()
    return latency, result_file_path


def main(event):
    global t_network

    latencies = {}
    timestamps = {}
    
    timestamps["starting_time"] = time.time()
    input_bucket = event['input_bucket']
    object_key = event['object_key']
    output_bucket = event['output_bucket']
    endpoint_url = event['endpoint_url']
    aws_access_key_id = event['aws_access_key_id']
    aws_secret_access_key = event['aws_secret_access_key']
    metadata = event['metadata']

    s3_client = boto3.client('s3',
                    endpoint_url=endpoint_url,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key)

    download_path = tmp+'{}{}'.format(uuid.uuid4(), object_key)

    start = time.time()
    s3_client.download_file(input_bucket, object_key, download_path, Config=config)
    download_latency = time.time() - start
    latencies["download_data"] = download_latency
    t_network += download_latency

    video_processing_latency, upload_path = video_processing(object_key, download_path)
    latencies["function_execution"] = video_processing_latency

    start = time.time()
    s3_client.upload_file(upload_path, output_bucket, upload_path.split("/")[FILE_PATH_INDEX], Config=config)
    upload_latency = time.time() - start
    latencies["upload_data"] = upload_latency
    t_network += upload_latency
    timestamps["finishing_time"] = time.time()

    return {"latencies": latencies, "timestamps": timestamps, "metadata": metadata, "total": latencies["download_data"] + latencies["upload_data"] + latencies["function_execution"]}


# main({
#     'input_bucket': 'input',
#     'object_key': 'SampleVideo_1280x720_10mb.mp4',
#     'output_bucket': 'output',
#     'endpoint_url': 'http://127.0.0.1:9000',
#     'aws_access_key_id': 'root',
#     'aws_secret_access_key': 'password',
#     'metadata': None,
# })
handler = main
fn_name = 'testcases/fn_py_video_processing'

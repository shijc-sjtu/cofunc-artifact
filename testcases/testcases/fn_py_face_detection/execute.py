import boto3
from boto3.s3.transfer import TransferConfig
import uuid
import cv2

tmp = "/tmp/"
FILE_NAME_INDEX = 0
FILE_PATH_INDEX = 2

config = TransferConfig(use_threads=False)

def image_processing(object_key, image_path, model_path):
    file_name = object_key.split(".")[FILE_NAME_INDEX]
    result_file_path = tmp+file_name+'-detection.jpg'

    face_cascade = cv2.CascadeClassifier(model_path)
        
    frame = cv2.imread(image_path)

    gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

    faces = face_cascade.detectMultiScale(gray_frame, 1.3, 5)

    for (x, y, w, h) in faces:
        cv2.rectangle(frame, (x, y), (x+w, y+h), (255, 0, 0), 2)

    cv2.imwrite(result_file_path, frame)

    return result_file_path


def main(event):
    global t_network

    input_bucket = event['input_bucket']
    object_key = event['object_key']
    output_bucket = event['output_bucket']
    model_object_key = event['model_object_key']
    model_bucket = event['model_bucket']
    endpoint_url = event['endpoint_url']
    aws_access_key_id = event['aws_access_key_id']
    aws_secret_access_key = event['aws_secret_access_key']
    metadata = event['metadata']

    s3_client = boto3.client('s3',
                    endpoint_url=endpoint_url,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key)

    download_path = tmp + '{}{}'.format(uuid.uuid4(), object_key)
    model_path = tmp + '{}{}'.format(uuid.uuid4(), model_object_key)

    start = time.time()
    s3_client.download_file(input_bucket, object_key, download_path, Config=config)
    s3_client.download_file(model_bucket, model_object_key, model_path, Config=config)
    download_data = time.time() - start
    t_network += download_data

    upload_path = image_processing(object_key, download_path, model_path)

    start = time.time()
    s3_client.upload_file(upload_path, output_bucket, upload_path.split("/")[FILE_PATH_INDEX], Config=config)
    upload_data = time.time() - start
    t_network += upload_data


handler = main
fn_name = "testcases/fn_py_face_detection"
# main({
#         'input_bucket': 'input',
#         'object_key': 'sample-image.jpg',
#         'model_object_key': 'haarcascade_frontalface_default.xml',
#         'output_bucket': 'output',
#         'model_bucket': 'input',
#         'endpoint_url': 'http://127.0.0.1:9000',
#         'aws_access_key_id': 'root',
#         'aws_secret_access_key': 'password',
#         'metadata': None,
# })
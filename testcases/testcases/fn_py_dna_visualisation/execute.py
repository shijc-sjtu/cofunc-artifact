import io, json, time
# using https://squiggle.readthedocs.io/en/latest/
from squiggle import transform

import storage
client = storage.storage.get_instance()


def handler(event):
    global t_network

    input_bucket = event.get('bucket').get('input')
    output_bucket = event.get('bucket').get('output')
    key = event.get('object').get('key')
    download_path = '/tmp/{}'.format(key)

    download_begin = time.time()
    client.download(input_bucket, key, download_path)
    download_stop = time.time()
    data = open(download_path, "r").read()

    process_begin = time.time()
    result = transform(data)
    process_end = time.time()
    

    buf = io.BytesIO(json.dumps(result).encode())
    buf.seek(0)
    upload_begin = time.time()
    key_name = client.upload_stream(output_bucket, key, buf)
    upload_stop = time.time()
    buf.close()

    download_time = download_stop - download_begin
    upload_time = upload_stop - upload_begin
    process_time = process_end - process_begin

    t_network = download_time + upload_time


fn_name = 'testcases/fn_py_dna_visualisation'
# handler({
#     'bucket': {
#         'input': 'input',
#         'output': 'output',
#     },
#     'object': {
#         'key': 'bacillus_subtilis.fasta',
#     }
# })

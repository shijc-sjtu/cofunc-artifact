import time
import os
import gzip


def handler(request):
    file_size = request['file_size']
    file_write_path = '/tmp/file'

    start = time.time()
    with open(file_write_path, 'wb') as f:
        f.write(os.urandom(file_size * 1024 * 1024))
    disk_latency = time.time() - start

    with open(file_write_path, 'rb') as f:
        start = time.time()
        with gzip.open('/tmp/result.gz', 'wb') as gz:
            gz.writelines(f)
        compress_latency = time.time() - start

    return "disk latency : " + str(disk_latency) \
           + "/ compress latency : " + str(compress_latency)


fn_name = 'testcases/fn_py_gzip'

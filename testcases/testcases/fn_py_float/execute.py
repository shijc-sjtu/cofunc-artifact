import math
import time


def float_operations(n):
    start = time.time()
    for i in range(0, n):
        sin_i = math.sin(i)
        cos_i = math.cos(i)
        sqrt_i = math.sqrt(i)
    latency = time.time() - start
    return latency


def main(event):
    latencies = {}
    timestamps = {}
    timestamps["starting_time"] = time.time()
    n = int(event['n'])
    metadata = event['metadata']
    latency = float_operations(n)
    latencies["function_execution"] = latency
    timestamps["finishing_time"] = time.time()
    return {"latencies": latencies, "timestamps": timestamps, "metadata": metadata}


# main({
#     'n': 100000,
#     'metadata': None,
# })
fn_name = 'testcases/fn_py_float'
handler = main

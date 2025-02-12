import numpy as np


def matmul(n):
    A = np.random.rand(n, n)
    B = np.random.rand(n, n)

    C = np.matmul(A, B)


def main(event):
    n = int(event['n'])
    result = matmul(n)


# main({'n': 1000, 'metadata': None})
handler = main
fn_name = 'testcases/fn_py_matmul'

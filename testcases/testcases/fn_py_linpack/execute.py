from numpy import matrix, linalg, random


def linpack(n):
    # LINPACK benchmarks
    ops = (2.0 * n) * n * n / 3.0 + (2.0 * n) * n

    # Create AxA array of random numbers -0.5 to 0.5
    A = random.random_sample((n, n)) - 0.5
    B = A.sum(axis=1)

    # Convert to matrices
    A = matrix(A)
    B = matrix(B.reshape((n, 1)))

    # Ax = B
    x = linalg.solve(A, B)


def main(event):
    n = int(event['n'])
    result = linpack(n)


# main({'n': 1000, 'metadata': None})
handler = main
fn_name = 'testcases/fn_py_linpack'

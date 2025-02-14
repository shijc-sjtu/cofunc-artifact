#!/bin/python
import os
import json
import numpy as np

def collect_log_file(filename):
    if not os.path.exists(filename):
        return None
    results = []
    with open(filename) as file:
        for line in file:
            results.append(json.loads(line.strip()))
    avg_result = dict()
    for key in results[0]:
        avg_result[key] = np.average([result[key] for result in results])
    return avg_result

cofunc_fetch = collect_log_file("log/chain_py_finra/fn_py_finra_fetch_fast/sc_fork.log")
cofunc_audit = collect_log_file("log/chain_py_finra/fn_py_finra_audit_fast/sc_fork_200.log")
kata_fetch = collect_log_file("log/chain_py_finra/fn_py_finra_fetch_slow/kata_launch.log")
kata_audit = collect_log_file("log/chain_py_finra/fn_py_finra_audit_slow/kata_launch_200.log")

cofunc = cofunc_fetch["t_e2e"] + cofunc_audit["t_e2e"]
kata = kata_fetch["t_e2e"] + kata_audit["t_e2e"]

if __name__ == "__main__":
    result = f"CoFunc:        {cofunc}s\n" + \
             f"Kata-CVM:      {kata}s\n" + \
             f"Optimization:  {kata / cofunc}x"
    with open("plots/finra.txt", "w") as file:
        file.write(result)
    print(result)

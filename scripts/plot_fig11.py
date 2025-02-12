#!/bin/python
import os
import json
import numpy as np


apps = {
    "fn_py_bfs": (["fn_py_bfs"], True),
    "fn_py_chameleon": (["fn_py_chameleon"], True),
    "fn_py_compression": (["fn_py_compression"], True),
    "fn_py_duplicator": (["fn_py_duplicator"], True),
    "fn_py_face_detection": (["fn_py_face_detection"], True),
    "fn_py_float": (["fn_py_float"], True),
    "fn_py_gzip": (["fn_py_gzip"], True),
    "fn_py_image_processing": (["fn_py_image_processing"], True),
    "fn_py_json": (["fn_py_json"], True),
    "fn_py_linpack": (["fn_py_linpack"], True),
    "fn_py_matmul": (["fn_py_matmul"], True),
    "fn_py_mst": (["fn_py_mst"], True),
    "fn_py_pagerank": (["fn_py_pagerank"], True),
    "fn_py_pyaes": (["fn_py_pyaes"], True),
    "fn_py_sentiment": (["fn_py_sentiment"], True),
    "fn_py_thumbnailer": (["fn_py_thumbnailer"], True),
    "fn_py_uploader": (["fn_py_uploader"], True),
    "fn_py_video_processing": (["fn_py_video_processing"], True),
    "fn_py_dna_visualisation": (["fn_py_dna_visualisation"], True),
    "fn_js_auth": (["fn_js_auth"], False),
    "fn_js_dynamic_html": (["fn_js_dynamic_html"], False),
    "fn_js_encrypt": (["fn_js_encrypt"], False),
    "fn_js_thumbnailer": (["fn_js_thumbnailer"], False),
    "fn_js_uploader": (["fn_js_uploader"], False),
    "chain_js_alexa": (
        ["chain_js_alexa/fn_js_alexa_frontend",
         "chain_js_alexa/fn_js_alexa_interact",
         "chain_js_alexa/fn_js_alexa_smarthome",
         "chain_js_alexa/fn_js_alexa_tv"], False),
    "chain_py_map_reduce": (
        ["chain_py_map_reduce/fn_py_mapper",
         "chain_py_map_reduce/fn_py_reducer"], True),
    "chain_js_data_analysis": ([
        "chain_js_data_analysis/fn_js_wage_analysis_merit_percent",
        "chain_js_data_analysis/fn_js_wage_analysis_realpay",
        "chain_js_data_analysis/fn_js_wage_analysis_result",
        "chain_js_data_analysis/fn_js_wage_analysis_total",
        "chain_js_data_analysis/fn_js_wage_fillup"], False),
}

native_cow_latency = 1e-9 * \
    float(open('testcases/testcases/microbenchmarks/cow/exec_log').readlines()[-1].strip())

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


def collect_fn(fn_name, native_fork):
    log_dir = f"log/{fn_name}/"
    kata_log_filename = f"{log_dir}/kata_launch.log"
    native_log_filename = f"{log_dir}/lean_{'fork' if native_fork else 'launch'}.log"
    cofunc_log_filename = f"{log_dir}/sc_fork.log"

    kata_result = collect_log_file(kata_log_filename)
    native_result = collect_log_file(native_log_filename)
    cofunc_result = collect_log_file(cofunc_log_filename)

    cofunc = cofunc_result["t_e2e"]
    
    # Linux does not support multi-threading fork
    if native_fork:
        native = native_result["t_e2e"]
    else:
        # Emulate fork startup and CoW overhead
        native = cofunc_result["t_boot_lean"] + cofunc_result["t_boot_func"] + \
                 native_result["t_exec"] + cofunc_result["n_cow"] * native_cow_latency

    if kata_result is not None:
        # Emulate measurement and encryption overhead
        kata = kata_result["t_e2e"] + cofunc_result["t_encrypt_exec"] + cofunc_result["t_attest_import"]
    else:
        # SEVeriFast crashes when memory > 1GB, which is required for fn_py_dna_visualisation
        assert fn_name == "fn_py_dna_visualisation"
        native_result = collect_log_file(f"{log_dir}/lean_launch.log")
        kata_boot_latency = collect_log_file("log/fn_py_gzip/kata_launch.log")["t_boot_cntr"]
        kata = kata_boot_latency + native_result["t_e2e"] + cofunc_result["t_encrypt_exec"] + cofunc_result["t_attest_import"]

    return (kata, native, cofunc)
    

def collect_app(fn_names, native_fork):
    data = [collect_fn(fn_name, native_fork) for fn_name in fn_names]
    kata = sum([entry[0] for entry in data])
    native = sum([entry[1] for entry in data])
    cofunc = sum([entry[2] for entry in data])
    return (kata, native, cofunc)


def collect():
    results = dict()
    for app_name, (fn_names, native_fork) in apps.items():
        results[app_name] = collect_app(fn_names, native_fork)
    return results


def print_table(results):
    print(f"{'APP':<24}\tK\tN\tC\tOP\tOV")
    for app_name, (kata, native, cofunc) in results.items():
        optimization = kata / cofunc
        overhead = (cofunc - native) / native * 100
        print(f"{app_name:<24}\t{kata:.3f}\t{native:.3f}\t{cofunc:.3f}\t{optimization:.3f}\t{overhead:.3f}")


print_table(collect())

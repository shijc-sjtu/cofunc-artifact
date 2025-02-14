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
    "chain_js_data_analysis": (
        ["chain_js_data_analysis/fn_js_wage_analysis_merit_percent",
         "chain_js_data_analysis/fn_js_wage_analysis_realpay",
         "chain_js_data_analysis/fn_js_wage_analysis_result",
         "chain_js_data_analysis/fn_js_wage_analysis_total",
         "chain_js_data_analysis/fn_js_wage_fillup"], False),
}

native_cow_latency = 1e-9 * \
    float(open('log/microbenchmarks/cow/result').readlines()[-1].strip())

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
    cofunc_launch_log_filename = f"{log_dir}/sc_launch.log"

    kata_result = collect_log_file(kata_log_filename)
    native_result = collect_log_file(native_log_filename)
    cofunc_result = collect_log_file(cofunc_log_filename)
    cofunc_launch_result = collect_log_file(cofunc_launch_log_filename)

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
        kata = kata_result["t_e2e"] + cofunc_launch_result["t_encrypt_exec"] + cofunc_launch_result["t_attest_import"]
    else:
        # SEVeriFast crashes when memory > 1GB, which is required for fn_py_dna_visualisation
        assert fn_name == "fn_py_dna_visualisation"
        native_launch_result = collect_log_file(f"{log_dir}/lean_launch.log")
        kata_boot_latency = collect_log_file("log/fn_py_gzip/kata_launch.log")["t_boot_cntr"]
        kata = kata_boot_latency + native_launch_result["t_e2e"] + cofunc_launch_result["t_encrypt_exec"] + cofunc_launch_result["t_attest_import"]

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


def gen_table(results):
    lines = []
    lines.append("K: Kata-CVM (s), N: Native (s), C: CoFunc (s), OP: Optimization, OV: Overhead")
    lines.append("OP = K / C, OV = (C / N - 1) * 100")
    lines.append("-----------------------------------------------------------------------------")
    lines.append(f"{'Function':<24}\t{'K':<4}\t{'N':<4}\t{'C':<4}\t{'OP':<5}\t{'OV':<5}")
    optimizations = []
    overheads = []
    for app_name, (kata, native, cofunc) in results.items():
        optimization = kata / cofunc
        optimizations.append(optimization)
        overhead = (cofunc - native) / native * 100
        overheads.append(overhead)
        lines.append(f"{app_name:<24}\t{kata:.3f}\t{native:.3f}\t{cofunc:.3f}\t{optimization:.3f}\t{overhead:.3f}")
    lines.append(f"{'Min':<24}\t{' ':<4}\t{' ':<4}\t{' ':<4}\t{min(optimizations):.3f}\t{min(overheads):.3f}")
    lines.append(f"{'Max':<24}\t{' ':<4}\t{' ':<4}\t{' ':<4}\t{max(optimizations):.3f}\t{max(overheads):.3f}")
    lines.append(f"{'Avg':<24}\t{' ':<4}\t{' ':<4}\t{' ':<4}\t{np.average(optimizations):.3f}\t{np.average(overheads):.3f}")
    return "\n".join(lines)


if __name__ == "__main__":
    results = collect()
    table = gen_table(results)
    with open("plots/fig11.txt", "w") as file:
        file.write(table)
    print(table)


#########################


import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

mpl.rcParams["hatch.linewidth"] = 0.8 

x_tick_names = [
    "fn_py_face_detection",
    "fn_py_image_processing",
    "fn_py_sentiment",
    "fn_py_video_processing",
    "fn_py_compression",
    "fn_py_dna_visualisation",
    "fn_js_uploader",
    "fn_js_thumbnailer",
    "chain_js_alexa",
]

x_tick_names_short = [
    "face\n(py)",
    "image\n(py)",
    "sentiment\n(py)",
    "video\n(py)",
    "compress\n(py)",
    "dna\n(py)",
    "upload\n(js)",
    "thumbnail\n(js)",
    "alexa\n(js)",
]

fontsize = 8
latex_col = 241.02039  ## pt

sbar_space = 0.05
sbar_wz = 0.3 - sbar_space
n_sbar = 3
whole_bar_width = (sbar_space + sbar_wz) * (n_sbar - 1)
width = whole_bar_width  # the width of the bars: can also be len(x) sequence
linewidth = 0.5

NATIVE = "Native (SEV)"
COFUNC = "CoFunc (SEV)"
KATA = "Kata-CVM (SEV)"

color_list = {NATIVE: '#ced4da', COFUNC: '#adb5bd', KATA: '#6c757d'}

app_dict = {
    NATIVE: [results[app_name][1] for app_name in x_tick_names],
    COFUNC: [results[app_name][2] for app_name in x_tick_names],
    KATA:   [results[app_name][0] for app_name in x_tick_names],
}

def adjust_ax_style(ax, disable=True):
    if disable:
        ax.tick_params(which="major", length=0, axis="x")
        ax.tick_params(which="minor", length=0, axis="x")
        ax.tick_params(which="minor", length=0, axis="y")
        ax.tick_params(which="major", length=2, axis="y")
    ax.tick_params(axis="y", labelsize=fontsize)
    ax.tick_params(axis="y", which="major", pad=2)
    # ax.yaxis.set_tick_params(width=0.2)

    for s in ax.spines:
        ax.spines[s].set_linewidth(0.1)

    ax.yaxis.grid(color='black', linestyle=(0, (5, 10)), linewidth=0.1, zorder=0)

def plot(fig, spec):
    ax =  fig.add_subplot(spec)
    labels = np.arange(start=-1, stop=-1+1.5*len(x_tick_names), step=1.5)
    
    # normalized_values = {
    #     NATIVE: [app_dict[NATIVE][i] / app_dict[KATA][i] for i in range(len(x_tick_names))],
    #     COFUNC: [app_dict[COFUNC][i] / app_dict[KATA][i] for i in range(len(x_tick_names))],
    #     KATA:   [app_dict[KATA][i] / app_dict[KATA][i] for i in range(len(x_tick_names))],
    # }

    for i, k in enumerate(app_dict):
        hatch = "///////" if k == COFUNC else ""
        ax.bar(
            labels + (sbar_wz + sbar_space) * i,
            app_dict[k],
            sbar_wz,
            label=k,
            hatch=hatch,
            lw=0.05,
            edgecolor="black",
            color=color_list[k],
            zorder=3
        )
    
    ax.set_ylabel("Latency (s)", fontsize=fontsize, labelpad=4)
    ax.tick_params(axis="y", labelsize=fontsize)
    ax.tick_params(axis="y", which="major", pad=1)
    
    leg = ax.legend(
        fontsize=fontsize,
        frameon=False,
        loc="upper center",
        handlelength=1.2,
        labelspacing=0.1,
        ncol=3,
        bbox_to_anchor=(0.48, 1.4),
        handletextpad=0.3,
    )
    leg.set_zorder(1)

    adjust_ax_style(ax)
    ax.set_yscale('log')

    ax.set_xticks(
        (labels + whole_bar_width / 2),
        x_tick_names_short,
        rotation=10,
        fontsize=fontsize,
        #labelpad = -5,
    )     
    ax.tick_params(axis='x', labelsize=fontsize)   

def get_figsize(columnwidth, wf=0.5, hf=(5.**0.5-1.0)/2.0):
    """Parameters:
    - wf [float]:  width fraction in columnwidth units
    - hf [float]:  height fraction in columnwidth units.
                       Set by default to golden ratio.
    - columnwidth [float]: width of the column in latex. Get this from LaTeX 
                               using \\showthe\\columnwidth
    Returns:  [fig_width,fig_height]: that should be given to matplotlib
      """
    fig_width_pt = columnwidth*wf 
    inches_per_pt = 1.0/72.27               # Convert pt to inch
    fig_width = fig_width_pt*inches_per_pt  # width in inches
#    fig_height = fig_width*hf      # height in inches
    fig_height = columnwidth * hf * inches_per_pt
    return [fig_width, fig_height]

if __name__ == "__main__":
    plt.rcParams["lines.markersize"] = 3

    fig = plt.figure(constrained_layout=False)
    spec = gridspec.GridSpec(ncols=1, nrows=1, figure=fig)

    plot(fig, spec[0, 0])

    fig.set_size_inches(get_figsize(latex_col, wf=1.0 * 2 + 0.05, hf=0.105 * 3))
    fig.subplots_adjust(wspace=0.12, hspace=0.18)

    fig.savefig(
        "plots/fig11.pdf",
        dpi=1000,
        format="pdf",
        bbox_inches="tight",
    )

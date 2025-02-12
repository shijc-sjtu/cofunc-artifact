# CoFunc Artifact

This is the artifact for the paper "Serverless Functions Made Confidential and Efficient with Split Containers".

The artifact includes the following components:
* The source code of CoFunc system, including the CVM OS code (`cvm_os`), the shadow container code (`shadow_container`) and the patches for the host Linux/QEMU (`patches`).
* The serverless functions utilized for the experiment (`testcases/testcases`).
* The scripts for conducting the experiment (`scripts` and `testcases/tools`).

## Hardware dependencies

The artifact requires AMD CPUs with SEV-SNP support and a minimum of 8 GB of memory.
It has been tested on EPYC-7T83 and EPYC-9654 machines.
A test server is available for AE reviewers (please refer to the artifact appendix).

## Software dependencies

The artifact works on an SEV-SNP version of the Linux kernel ([link](https://github.com/AMDESE/linux.git), branch `svsm-preview-hv-v2`), along with the modifications in `patches/linux.patch`.
The following dependencies are required for building the artifact and running the experiment: Docker, screen, Python 3 (with matplotlib, numpy, boto3, CouchDB) and gcc.

## Set-up

### Installation

For reviewers using the test server, the artifact is already installed, and no further steps are required.

For other users, the artifact can be installed by following these steps:

1. Download the host kernel code and apply the patch.

2. Build the kernel and reboot with the new kernel. Ensure that cgroup v2 is enabled with the following kernel parameter:

```
systemd.unified_cgroup_hierarchy=1
```

3. Build CVM OS, shadow container, serverless functions and some other components with the script `scripts/build.sh`.

4. Enable transparent huge pages with the following command.

```Bash
echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
echo always | sudo tee /sys/kernel/mm/transparent_hugepage/shmem_enabled
```

4. Create a tap device on the host OS with the following command, with `eth0` replaced with the name of your physical network card.

```Bash
sudo scripts/init_tap.sh eth0
```

5. Fill the configuration file `config.json` with the IP of the host machine (`host_ip` field) and a static IP in your local network for Kata-CVM containers (`cntr_ip` field).

### Basic Test

Run the script `scripts/run_simple.sh`, which executes a serverless function using split container (without lean container optimization).
The script will output the function's running time as follows.

```
{
    "timestamp": 1739355161.0195742,
    "t_boot": 1.0877048969268799,
    "t_exec": 0.6204202175140381
}
```

## Evaluation Workflow

### Major Claims

(C1): For the evaluated functions, CoFunc demonstrates significant performance improvements (up to 60x) compared with Kata-CVM, while incurring <14% performance overhead compared with Native. This is proven by the experiment (E1) described in Section 7.1, whose results are illustrated in Figure 11.

### Experiments

(E1): Evaluate the end-to-end latency of handling a single request for the functions with CVM, Kata-CVM, and Native. Run the script `scripts/run_fig11.sh`. The script will output the execution time of each function and the overhead/optimization of CoFunc compared to Native/Kata-CVM. Additionally, the script will generate a figure at `plots/fig11.pdf`, which can be compared with Figure 11.

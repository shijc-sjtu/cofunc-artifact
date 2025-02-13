#!/bin/bash

set -e

tools=$(dirname $0)/..
tools=$(realpath $tools)
assets=$tools/../severifast-assets
mem_size=$(cat memory)
n=${1:-1}

mem_size=$(bc <<< "${mem_size}+128")
if [[ $mem_size -gt 1024 ]]; then
    mem_size=1024
fi

clean() {
    rm -rf .fc-config
    mkdir .fc-config
}

build() {
    INITRD_HASH_PATH="$assets/hashes/initrd-aws-lz4.img.hash"
    INITRD_HASH_CONF="\"initrd_hash_path\": \"${INITRD_HASH_PATH}\","

    FIRMWARE="$assets/images/snp-fw.bin"
    SNP_CONF="\"snp\": true,"
    KERNEL_HASHES="$assets/hashes/bzImage-aws-6.4-lz4.hash"
    POLICY="5"
    LAUNCH_BLOB="$assets/certs/launch_blob.bin"
    GODH_CERT="$assets/certs/godh.cert"
    SEV_CONF=$(echo "  \"sev-config\": {"\
            "\"firmware_path\": \"${FIRMWARE}\","\
                "${SNP_CONF}"\
            "\"kernel_hash_path\": \"${KERNEL_HASHES}\","\
            "${INITRD_HASH_CONF}"\
            "\"policy\": ${POLICY},"\
            "\"session_path\": \"${LAUNCH_BLOB}\","\
            "\"dh_cert\": \"${GODH_CERT}\""\
            "},")

    NET_DEV=tap$1
    NET_DEV_CONF=$(echo " \"network-interfaces\": ["\
			    "{"\
			    "\"iface_id\": \"eth0\","\
			    "\"guest_mac\": \"AA:FC:00:00:00:$(printf '%02x' $1)\","\
			    "\"host_dev_name\": \"${NET_DEV}\""\
			    "}],")

    KERNEL="$assets/images/bzImage-aws-6.4-lz4"
    KERNEL_CONF="    \"kernel_image_path\": \"${KERNEL}\","

    INITRD="$assets/images/initrd-aws-lz4.img"
    INITRD_CONF="    \"initrd_path\": \"${INITRD}\""

    ROOTFS="$(pwd)/.fc-rootfs/rootfs.ext4"
    # MEM_SIZE=$(bc <<< "${mem_size}+128")
    MEM_SIZE=$mem_size
    CMDLINE="reboot=k panic=-1 noapic noapictimer nosmp acpi=off console=ttyS0 swiotlb=513 quiet root=/dev/vda i8042.noaux i8042.nopnp i8042.dumbkbd i8042.nomux rdinit=/bin/xxx init=/bin/myinit myip=$2"
    ROOTFS_CONF="      \"path_on_host\": \"${ROOTFS}\","
    BOOT_ARGS_CONF="    \"boot_args\": \"$CMDLINE\","
    MEM_CONF="    \"mem_size_mib\": ${MEM_SIZE},"

    HUGEPAGES="    \"hugepages\": true"

    FC_CONFIG_BASE="$assets/config/vm_config.json"
    FC_CONFIG=".fc-config/vm_config_$1.json"
    cat ${FC_CONFIG_BASE} | 
    sed "s|.*kernel_image_path.*|${KERNEL_CONF}|" |
    sed "s|.*path_on_host.*|${ROOTFS_CONF}|" |
    sed "s|.*initrd_path.*|${INITRD_CONF}|" |
    sed "s|.*boot_args.*|${BOOT_ARGS_CONF}|" |
    sed "s|.*mem_size_mib.*|${MEM_CONF}|" |
    sed "s|.*hugepages.*|${HUGEPAGES}|" |
    sed "s|.*network-interfaces.*|${NET_DEV_CONF}|" |
    sed "s|.*sev-config.*|${SEV_CONF}|" > ${FC_CONFIG}
}

clean

if [[ $1 == "clean" ]]; then
    exit 0
fi

for i in $(seq $n); do
    build $i 172.16.1.$i/16
done

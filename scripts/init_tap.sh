#!/bin/bash -e

if [[ $1 == "" ]]; then
    echo "Usage: init_tap.sh eth"
fi

BR=br0
TAP=tap1
ETH=$1

ip tuntap add dev $TAP mode tap
ip link set $TAP up
ip addr flush dev $ETH
brctl addbr $BR
brctl addif $BR $TAP
brctl addif $BR $ETH
ip link set $BR up
dhclient $BR


# echo madvise | sudo tee /sys/kernel/mm/transparent_hugepage/enabled 
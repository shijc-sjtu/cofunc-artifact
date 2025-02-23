#!/bin/bash -ex

BR=br0
ETH=$1
N=${2:-1}

ip link set $BR down || true
brctl delbr $BR || true
brctl addbr $BR
ip addr flush dev $ETH
brctl addif $BR $ETH
ip link set $BR up
dhclient $BR
ip addr add 172.16.0.1/16 dev $BR

for i in $(seq $N); do
    TAP="tap$i"

    ip tuntap del $TAP mode tap || true
    ip tuntap add $TAP mode tap
    sudo brctl addif $BR $TAP
    sudo ip link set $TAP up
done

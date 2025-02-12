#!/bin/bash

set -e
set -o xtrace

n=${1:-1}

BR=br-sjc

sudo ip link set $BR down || true
sudo brctl delbr $BR || true
sudo brctl addbr $BR
sudo ip addr add 172.16.0.1/16 dev $BR
sudo ip link set $BR up

for i in $(seq $n); do
    NET_DEV="tap$i"

    HOST_IFACE=eth1
    MTU=1500
    sudo ip tuntap del ${NET_DEV} mode tap || true
    sudo ip tuntap add ${NET_DEV} mode tap
    sudo brctl addif $BR ${NET_DEV}
    # sudo ip addr add 172.16.0.$i/16 dev ${NET_DEV}
    sudo ip link set ${NET_DEV} up
    sudo ip link set dev ${NET_DEV} mtu ${MTU}
    # echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
    # sudo iptables -t nat -A POSTROUTING -o "$HOST_IFACE" -j MASQUERADE
    # sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    # sudo iptables -A FORWARD -i ${NET_DEV} -o ${HOST_IFACE} -j ACCEPT
done
# echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
# sudo iptables -t nat -A POSTROUTING -o "$HOST_IFACE" -j MASQUERADE
# sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# sudo iptables -A FORWARD -i ${NET_DEV} -o ${HOST_IFACE} -j ACCEPT

# set init for doing attestation
# sudo nginx -s stop > /dev/null 2>&1
# sudo nginx > /dev/null 2>&1


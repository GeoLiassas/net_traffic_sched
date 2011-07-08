#!/bin/sh
#TODO Get dev name from input
#TODO Check super user
modprobe iptable_nat
iptables -t nat -A POSTROUTING -o eth6 -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward

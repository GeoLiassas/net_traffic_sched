#!/bin/sh

rmmod k_flow_control
insmod ./k_flow_control.ko target="192.168.10.4"

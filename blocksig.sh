#!/bin/sh

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 pid"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

bpftrace -e "kprobe:__x64_sys_kill { if (arg1 == $1) { printf(\"Signal blocked for $1\n\"); override(0); } }" --unsafe

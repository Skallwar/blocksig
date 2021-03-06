#!/usr/bin/python

from bcc import BPF
from bcc.utils import ArgString, printb
from ctypes import *
import argparse
import tempfile
import time
import os

# define BPF program
def parse_args():
    parser = argparse.ArgumentParser(description='Blocksig is a tool to block certain or all signal to be recived by given pids')
    parser.add_argument('-p', dest='pids', nargs='+', default=[], metavar='pid', help='List of pid to protect')
    parser.add_argument('-s', dest='sigs', nargs='+', default=[], metavar='signal_num', help='List of signal to block. If no signal is specified, they are all blocked')
    parser.add_argument('--auto-protect', action=argparse.BooleanOptionalAction, default=True, help='Whether to protect blocksig itself or not')
    args = parser.parse_args()

    return args


def initialize_bpf(args):
    b = BPF(src_file="blocksig.c")
    kill_fnname = b.get_syscall_fnname('kill')
    b.attach_kprobe(event=kill_fnname, fn_name='syscall__kill')
    pids_map = b.get_table('pids')
    sigs_map = b.get_table('sigs')

    if args.auto_protect == True:
        args.pids.append(str(os.getpid()))
    for pid in args.pids:
        pids_map[c_int(int(pid))] = c_int(1)

    sig_array = [int(sig) for sig in args.sigs] if len(args.sigs) else range(1, 64)
    for sig in sig_array:
        sigs_map[sig] = c_int(1)

def wait_for_close():
# Create a tempfile and wait for its deletion
    tf = tempfile.NamedTemporaryFile(delete = False)
    print(f"This script might not be killable anymore. To stop it run ``rm {tf.name}``")

    try:
        while os.path.isfile(tf.name):
            time.sleep(0.5)
            continue
    except KeyboardInterrupt:
        tf.close()
        os.remove(tf.name)
        print('')

args = parse_args()
initialize_bpf(args)
wait_for_close()

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/__x64_sys_kill")
int BPF_KPROBE(__x64_sys_kill, pid_t pid, int sig)
{
	bpf_printk("Blocksig entry. pid = %d, sig = %i\n", pid, sig);

	return 0;
}

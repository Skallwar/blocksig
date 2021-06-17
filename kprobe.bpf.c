// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ENTRIES 8192

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, size_t);
	__type(value, pid_t);
} pids SEC(".maps");

SEC("kprobe/__x64_sys_kill")
int BPF_KPROBE(__x64_sys_kill, pid_t pid, int sig)
{
	size_t i = 0;
	pid_t elm = 0;
	bpf_map_update_elem(&pids, &i, &elm, BPF_ANY);
	/* pid_t *lookup_pid = bpf_map_lookup_elem(&pids, &i); */
	/* bpf_printk("Blocksig entry. pid = %d, sig = %i, lookup pid = %d\n", pid, */
	/* 	   sig, lookup_pid); */

	return 0;
}

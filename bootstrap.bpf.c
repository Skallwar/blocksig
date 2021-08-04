// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

SEC("kprobe/__x64_sys_kill")
int BPF_KPROBE(__x64_sys_kill, pid_t pid, int sig)
{
	pid_t idx = 0;
	u64 *need_block = bpf_map_lookup_elem(&exec_start, &idx);

	if (!need_block)
		return 1;

	bpf_printk("Pid = %d, need_block = %lu\n", idx, *need_block);

	return 0;
}

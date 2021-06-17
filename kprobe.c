// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <bpf/libbpf.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "kprobe.skel.h"
#include "vec/vec.h"

struct args {
	struct vec pids;
	struct vec sigs;
	size_t nb_pid;
	size_t nb_sig;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

static void cleanup_bpf(struct kprobe_bpf *skel)
{
	kprobe_bpf__destroy(skel);
}

static struct kprobe_bpf *setup_bpf(void)
{
	struct kprobe_bpf *skel;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Open load and verify BPF application */
	skel = kprobe_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return NULL;
	}

	int err = kprobe_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		return NULL;
	}

	/* Attach tracepoint handler */
	err = kprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		cleanup_bpf(skel);
		return NULL;
	}

	return skel;
}

struct args parse_args(int argc, char **argv)
{
	struct args args = { 0 };
	vec_init(&args.pids);
	vec_init(&args.sigs);

	int opt;

	while ((opt = getopt(argc, argv, "s:p:")) != -1) {
		switch (opt) {
		case 's':
			optind--;
			for (; optind < argc && *argv[optind] != '-';
			     optind++) {
				int *sig = malloc(sizeof(*sig));
				if (!sig)
					err(1, "");
				*sig = atoi(argv[optind]);
				if (!*sig || *sig > 31)
					err(1,
					    "%s is not a valid signal number",
					    argv[optind]);

				vec_push_back(&args.pids, sig);
			}
			break;
		case 'p':
			optind--;
			for (; optind < argc && *argv[optind] != '-';
			     optind++) {
				pid_t *pid = malloc(sizeof(*pid));
				if (!pid)
					err(1, "");
				*pid = atoi(argv[optind]);
				if (!*pid || *pid > 31)
					err(1,
					    "%s is not a valid signal number",
					    argv[optind]);

				vec_push_back(&args.pids, pid);
			}
			break;
		default: /* '?' */
			fprintf(stderr,
				"Usage: blocksig -s signal1, ..., signaln -p pid1, ..., pid2\n");
			exit(EXIT_FAILURE);
		}
	}

	/* if (optind >= argc) { */
	/*   fprintf(stderr, "Expected argument after options\n"); */
	/*   exit(EXIT_FAILURE); */
	/* } */

	return args;
}

int main(int argc, char **argv)
{
	struct args args = parse_args(argc, argv);
	int ret = 0;

	struct kprobe_bpf *skel = setup_bpf();
	if (!skel) {
		fprintf(stderr, "Failed to setup BPF\n");
		return 1;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n",
			strerror(errno));
		ret = 1;
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat "
	       "/sys/kernel/debug/tracing/trace_pipe`"
	       "to see output of the BPF programs.\n");

	while (!stop) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	cleanup_bpf(skel);
	return ret;
}

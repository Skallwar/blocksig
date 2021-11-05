#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(pids, int, u8);
BPF_ARRAY(sigs, u8, 65);

static u8 needs_block(u8 protected_pid, u8 protected_sig) {
    return protected_pid != 0 && protected_sig != 0;
}

int syscall__kill(struct pt_regs *ctx, int pid, int sig)
{

    u8 *protected_pid = pids.lookup(&pid);
    u8 *protected_sig = sigs.lookup(&sig);
    if (!protected_pid || !protected_sig)
        return 0;

    if (needs_block(*protected_pid, *protected_sig)) {
        bpf_trace_printk("Blocked signal %d for %d\\n", sig, pid);
        bpf_override_return(ctx, 0);
    }

    return 0;
}

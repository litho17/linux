#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = 2,
};

SEC("kprobe/sys_write")
int bpf_prog1(struct pt_regs *ctx)
{
	long t1 = bpf_ktime_get_ns();
	struct S {
		u64 pid;
		u64 cookie;
	} data;

	data.pid = bpf_get_current_pid_tgid();
	data.cookie = 0x12345678;

	bpf_perf_event_output(ctx, &my_map, 0, &data, sizeof(data));
	long t2 = bpf_ktime_get_ns();
	char fmt2[] = "\n\nTime elapsed (trace_output): %d\n\n";
	bpf_trace_printk(fmt2, sizeof(fmt2), (t2-t1));
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;

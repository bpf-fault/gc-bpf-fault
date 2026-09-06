/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The bpf_fault link command ABI: registering an address range with a
 * fault-ops link, and enabling or lifting write protection over it.
 *
 * These constants mirror the bpf-fault kernel tree
 * (tools/testing/selftests/bpf/bench_fault/wp_util.h) until they land in
 * system headers.
 */
#ifndef GC_FAULT_H
#define GC_FAULT_H

#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/types.h>

#ifndef BPF_LINK_FAULT_OPS_CMD
#define BPF_LINK_FAULT_OPS_CMD	38
#endif
#ifndef BPF_FAULT_FLAG_WP
#define BPF_FAULT_FLAG_WP	(1U << 0)
#endif
#ifndef BPF_FAULT_FLAG_INHERIT
#define BPF_FAULT_FLAG_INHERIT	(1U << 1)
#endif
#ifndef BPF_FAULT_WP_ENABLE
#define BPF_FAULT_WP_ENABLE	(1U << 0)
#endif
#ifndef BPF_FAULT_REGISTER
#define BPF_FAULT_REGISTER	(1U << 1)
#endif
#ifndef BPF_FAULT_UNREGISTER
#define BPF_FAULT_UNREGISTER	(1U << 2)
#endif

struct bpf_link_fault_cmd_attr {
	__u32		link_fd;
	__u32		flags;
	__u64		start;
	__u64		len;
} __attribute__((aligned(8)));

static inline int bpf_link_fault_cmd(int link_fd, __u64 start, __u64 len,
				     __u32 flags)
{
	struct bpf_link_fault_cmd_attr attr = {
		.link_fd = link_fd,
		.flags = flags,
		.start = start,
		.len = len,
	};

	return syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD, &attr, sizeof(attr));
}

#endif /* GC_FAULT_H */

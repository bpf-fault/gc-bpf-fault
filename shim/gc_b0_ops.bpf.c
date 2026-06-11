// SPDX-License-Identifier: GPL-2.0-only
/*
 * bpf_fault missing-fault handler for fault-driven Compressor compaction
 * (Class B).  The GC flips each 1 MiB region's physical pages into a linear
 * from-space arena (arena_base + (addr - space_base)) and slides/compacts
 * objects in place inside the arena.  Page states (one u64 per page of the
 * heap span, userspace-mmapable):
 *   0 = zero-fill (never compacted / tail beyond the compacted cursor)
 *   1 = staged    (arena holds the final compacted page contents)
 * On a missing fault: staged pages are copied from the arena into the
 * kernel-provided page (zero-copy install); state-0 pages stay zeroed.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

#define B0_ZERO_FILL 0
#define B0_STAGED 1

const volatile unsigned long space_base = 0;
const volatile unsigned long arena_base = 0;
const volatile unsigned long span_len = 0;

volatile __u64 b0_fault_count = 0;
volatile __u64 b0_staged_installs = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1); /* resized to span_len/4096 before load */
} page_state SEC(".maps");

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *page)
{
	unsigned long off = ops_ctx->address - space_base;
	__u32 idx;
	__u64 *st;
	int err = 0;

	__sync_fetch_and_add(&b0_fault_count, 1);
	if (off >= span_len)
		return 0;

	idx = off >> PAGE_SHIFT;
	st = bpf_map_lookup_elem(&page_state, &idx);
	if (st && *st == B0_STAGED) {
		err = bpf_probe_read_user(page, PAGE_SIZE,
					  (void *)(arena_base + off));
		__sync_fetch_and_add(&b0_staged_installs, 1);
	}
	return err;
}

SEC(".struct_ops.link")
struct fault_ops gc_b0_ops = {
	.handle_page_fault = (void *)handle_page_fault,
};

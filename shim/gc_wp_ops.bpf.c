// SPDX-License-Identifier: GPL-2.0-only
/*
 * bpf_fault WP handler for generational dirty-page tracking (Class A).
 *
 * On a write-protect fault, set the page's bit in a userspace-mmapable
 * dirty bitmap and allow the write (return 0 clears the WP marker for
 * the page).  This is the entire "write barrier": no signal, no handler
 * thread, no extra syscalls.
 *
 * heap_base and the bitmap size are set by userspace before load.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define PAGE_SHIFT 12

const volatile unsigned long heap_base = 0;

volatile __u64 wp_fault_count = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1); /* resized to nr_pages/64 before load */
} dirty_bitmap SEC(".maps");

SEC("struct_ops/handle_wp_fault")
int BPF_PROG(handle_wp_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *page)
{
	unsigned long idx = (ops_ctx->address - heap_base) >> PAGE_SHIFT;
	__u32 word = idx >> 6;
	__u64 *w;

	w = bpf_map_lookup_elem(&dirty_bitmap, &word);
	if (w)
		__sync_fetch_and_or(w, 1ULL << (idx & 63));
	__sync_fetch_and_add(&wp_fault_count, 1);
	return 0;
}

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *page)
{
	/* WP-only registration: missing faults are not intercepted. */
	return 0;
}

SEC(".struct_ops.link")
struct fault_ops gc_wp_ops = {
	.handle_page_fault = (void *)handle_page_fault,
	.handle_wp_fault = (void *)handle_wp_fault,
};

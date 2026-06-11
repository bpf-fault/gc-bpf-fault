// SPDX-License-Identifier: GPL-2.0-only
/*
 * bpf_fault missing-fault handler for concurrent-compaction page
 * materialization (Class B).
 *
 * The GC has staged page contents at from_base (in the real collector this
 * is the userspace-compacted page, ART-style; in the v2 design the handler
 * will additionally apply per-object reference fixups in-kernel).  On a
 * missing fault in to-space, copy the corresponding staged page directly
 * into the kernel-provided destination page: no signal, no UFFDIO_COPY,
 * and no extra page copy — the eBPF program writes the final page.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define PAGE_SIZE 4096

const volatile unsigned long to_base = 0;
const volatile unsigned long from_base = 0;
const volatile unsigned long region_len = 0;

volatile __u64 missing_fault_count = 0;

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *page)
{
	unsigned long off = ops_ctx->address - to_base;
	int err;

	if (off >= region_len)
		return 0;

	err = bpf_probe_read_user(page, PAGE_SIZE,
				  (void *)(from_base + off));
	__sync_fetch_and_add(&missing_fault_count, 1);
	return err;
}

SEC(".struct_ops.link")
struct fault_ops gc_compact_ops = {
	.handle_page_fault = (void *)handle_page_fault,
};

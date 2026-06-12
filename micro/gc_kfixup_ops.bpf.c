// SPDX-License-Identifier: GPL-2.0-only
/*
 * Class B v2 — IN-KERNEL compaction + reference fixup.
 *
 * Unlike B.0/B.1 (userspace slide-compacts objects into a from-space arena
 * and the handler just memcpys the staged page back), here the missing-fault
 * handler builds the to-space page itself, entirely in eBPF:
 *   1. For each object slot on the faulted to-space page, find its from-space
 *      source via the GC-provided new->old map and copy the object bytes.
 *   2. Rewrite each reference field to the referent's NEW address
 *      (forward()): ref' = to_base + old2new[ref_old_index] * OBJ_SIZE.
 * This is the GC analogue of the paper's fault-time dynamic-linker
 * relocation: read metadata, apply pointer fixups, all in the faulting
 * thread in-kernel — no userspace staging, no signal, no arena double-copy.
 *
 * Objects are fixed-size with a fixed reference layout for tractability
 * (the kernel mechanism is the point; variable layout / HotSpot oop maps are
 * the MMTk-integration problem).  Layout (8 x u64 words):
 *   [0] header (unused here)   [1] ref0   [2] ref1   [3..7] data
 * References hold a 1-based old object index (0 = null).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define PAGE_SIZE   4096
#define PAGE_SHIFT  12
#define OBJ_SIZE    64
#define OBJ_WORDS   (OBJ_SIZE / 8)
#define OBJS_PER_PAGE (PAGE_SIZE / OBJ_SIZE)   /* 64 */
#define REF0_WORD   1
#define REF1_WORD   2

const volatile unsigned long to_base = 0;     /* to-space base (registered) */
const volatile unsigned long from_base = 0;   /* from-space arena base */
const volatile unsigned long span_len = 0;
const volatile unsigned int  nr_objs = 0;     /* live object count */

volatile __u64 kfixup_faults = 0;
volatile __u64 kfixup_objs = 0;
volatile __u64 kfixup_refs = 0;

/* new object index -> old object index (1-based old; built by the GC). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);   /* resized to nr_objs */
} new2old SEC(".maps");

/* old object index (1-based) -> new object index (0-based); forward(). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);   /* resized to nr_objs + 1 */
} old2new SEC(".maps");

static __always_inline __u64 forward_ref(__u64 oldref)
{
	__u32 key, *newidx;

	if (oldref == 0)
		return 0;                /* null stays null */
	key = (__u32)oldref;             /* 1-based old index */
	newidx = bpf_map_lookup_elem(&old2new, &key);
	if (!newidx)
		return 0;
	return to_base + (__u64)(*newidx) * OBJ_SIZE;  /* new ADDRESS */
}

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *page)
{
	unsigned long off = ops_ctx->address - to_base;
	unsigned int first_new;
	int i;

	__sync_fetch_and_add(&kfixup_faults, 1);
	if (off >= span_len)
		return 0;

	first_new = (off >> PAGE_SHIFT) * OBJS_PER_PAGE;

	/* Materialize each object on this page directly into the
	 * kernel-provided page, applying reference fixups. */
	for (i = 0; i < OBJS_PER_PAGE; i++) {
		unsigned int nidx = first_new + i;
		__u32 key = nidx;
		__u32 *oldp;
		__u64 buf[OBJ_WORDS];
		unsigned long src;
		int w;

		if (nidx >= nr_objs)
			break;
		oldp = bpf_map_lookup_elem(&new2old, &key);
		if (!oldp || *oldp == 0)
			continue;
		/* from-space object at old index (1-based) -> arena offset */
		src = from_base + (__u64)(*oldp - 1) * OBJ_SIZE;
		if (bpf_probe_read_user(buf, OBJ_SIZE, (void *)src))
			return -14; /* -EFAULT */

		/* fixup the two reference words */
		buf[REF0_WORD] = forward_ref(buf[REF0_WORD]);
		buf[REF1_WORD] = forward_ref(buf[REF1_WORD]);
		__sync_fetch_and_add(&kfixup_refs, 2);

		/* write the fixed object into the page (bounded offset) */
		{
			unsigned int dst = (unsigned int)(i * OBJ_SIZE);

			if (dst + OBJ_SIZE > PAGE_SIZE)
				break;
			for (w = 0; w < OBJ_WORDS; w++)
				*(__u64 *)(page + dst + w * 8) = buf[w];
		}
		__sync_fetch_and_add(&kfixup_objs, 1);
	}
	return 0;
}

SEC(".struct_ops.link")
struct fault_ops gc_kfixup_ops = {
	.handle_page_fault = (void *)handle_page_fault,
};

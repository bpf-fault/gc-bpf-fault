// SPDX-License-Identifier: GPL-2.0-only
/*
 * Class B v2 — in-kernel compaction + reference fixup, BPF-ARENA edition.
 *
 * Everything the handler needs lives in a BPF arena (shared flat memory,
 * direct pointer access, no per-element map-lookup helper):
 *   - from_space[]: the live objects at their pre-compaction positions
 *   - new2old[]/old2new[]: the compaction renumbering (forward())
 *   - refbits[]: 1 bit per to-space word marking which words are references
 *     (the GC sets these during marking; this is the reference-identification
 *     solution that avoids HotSpot oop-map traversal in eBPF, and supports
 *     ARBITRARY reference layout, not fixed field offsets)
 *
 * On a missing fault the handler builds the to-space page entirely in-kernel:
 * copy each object from the arena, and for every word the refbit marks as a
 * reference, rewrite it to the referent's NEW address.  No userspace staging,
 * no signal, no probe_read.  This is the GC analogue of the paper's
 * arena-backed fault-time dynamic linker.
 *
 * Compiled with clang>=19 (native __BPF_FEATURE_ADDR_SPACE_CAST).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define __arena __attribute__((address_space(1)))
#define __arena_global __attribute__((address_space(1)))

#define PAGE_SIZE   4096
#define PAGE_SHIFT  12
#define OBJ_SIZE    64
#define OBJ_WORDS   (OBJ_SIZE / 8)
#define OBJS_PER_PAGE (PAGE_SIZE / OBJ_SIZE)   /* 64 */
#define MAX_OBJS    (1u << 20)                 /* arena-global capacity */

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1u << 16);  /* pages: ~256MB arena */
	__ulong(map_extra, 0x1ull << 44);
} arena SEC(".maps");

/* All shared state in the arena (userspace populates via skel->arena->...). */
__u64 __arena_global from_space[MAX_OBJS * OBJ_WORDS]; /* objects, by word */
__u32 __arena_global new2old[MAX_OBJS];                /* new idx -> old(1-based) */
__u32 __arena_global old2new[MAX_OBJS + 1];            /* old(1-based) -> new idx */
__u64 __arena_global refbits[(MAX_OBJS * OBJ_WORDS) / 64]; /* 1 bit / to-word */

const volatile unsigned long to_base = 0;
const volatile unsigned long span_len = 0;
const volatile unsigned int  nr_objs = 0;

volatile __u64 kfa_faults = 0;
volatile __u64 kfa_objs = 0;
volatile __u64 kfa_refs = 0;

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *octx,
	     unsigned char *page)
{
	unsigned long off = octx->address - to_base;
	unsigned int first_new;
	int i, w;

	__sync_fetch_and_add(&kfa_faults, 1);
	if (off >= span_len)
		return 0;

	first_new = (off >> PAGE_SHIFT) * OBJS_PER_PAGE;

	for (i = 0; i < OBJS_PER_PAGE; i++) {
		unsigned int nidx = first_new + i;
		unsigned int oldidx;       /* 1-based */
		unsigned int srcw, dstw;

		if (nidx >= nr_objs)
			break;
		oldidx = new2old[nidx];
		if (oldidx == 0)
			continue;
		srcw = (oldidx - 1) * OBJ_WORDS;       /* from-space word base */
		dstw = nidx * OBJ_WORDS;               /* to-space word base */

		for (w = 0; w < OBJ_WORDS; w++) {
			__u64 word = from_space[srcw + w];
			unsigned int tw = dstw + w;        /* to-space word index */

			/* reference word? forward it to the new address. */
			if (refbits[tw >> 6] & (1ULL << (tw & 63))) {
				if (word != 0)
					word = to_base +
					       (__u64)old2new[(__u32)word] * OBJ_SIZE;
				__sync_fetch_and_add(&kfa_refs, 1);
			}
			/* write the (possibly fixed) word into the page */
			if ((unsigned int)(i * OBJ_SIZE + w * 8 + 8) <= PAGE_SIZE)
				*(__u64 *)(page + i * OBJ_SIZE + w * 8) = word;
		}
		__sync_fetch_and_add(&kfa_objs, 1);
	}
	return 0;
}

SEC(".struct_ops.link")
struct fault_ops gc_kfixarena = {
	.handle_page_fault = (void *)handle_page_fault,
};

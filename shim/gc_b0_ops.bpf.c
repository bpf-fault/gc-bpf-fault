// SPDX-License-Identifier: GPL-2.0-only
/*
 * bpf_fault missing-fault handler for fault-driven Compressor compaction
 * (Class B / B v2).  The GC flips each 1 MiB region's physical pages into a
 * linear from-space arena (arena_base + (addr - space_base)) and slides
 * objects in place inside the arena.  Page states (one u64 per page,
 * userspace-mmapable):
 *   0 = zero-fill   1 = staged   2 = pending
 *
 * On a missing fault, staged pages are copied from the arena into the
 * kernel-provided page.  CLASS B v2 (in-kernel fixup): when `defer_fwd` is
 * set, references were NOT forwarded during staging; instead this handler
 * forwards each reference IN-KERNEL while materializing the page:
 *   - the reference bitmap (refbm_base, 1 bit / 4-byte compressed-oop slot)
 *     marks which dwords on the page are references;
 *   - each is decompressed (coops_base + (v << coops_shift)), forwarded via
 *     the Compressor's offset vector + mark bitmap (read directly from MMTk's
 *     side metadata: contiguous base + shift), and recompressed.
 * This is the GC analogue of a fault-time relocating dynamic linker.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

#define B0_ZERO_FILL 0
#define B0_STAGED 1
#define B0_PENDING 2

const volatile unsigned long space_base = 0;
const volatile unsigned long arena_base = 0;
const volatile unsigned long span_len = 0;

/* Class B v2 forward params (writable; set after JVM/metadata init). */
unsigned long mark_base = 0;     /* MMTk MARK_SPEC contiguous metadata base */
unsigned long offvec_base = 0;   /* MMTk OFFSET_VECTOR_SPEC metadata base */
unsigned long refbm_base = 0;    /* reference bitmap base (1 bit / 4 bytes) */
unsigned long coops_base = 0;    /* compressed-oops base */
unsigned int  coops_shift = 0;   /* compressed-oops shift */
unsigned int  defer_fwd = 0;     /* 1 = forward references in-kernel */

volatile __u64 b0_fault_count = 0;
volatile __u64 b0_staged_installs = 0;
volatile __u64 b0_refs_forwarded = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1); /* resized to span_len/4096 before load */
} page_state SEC(".maps");

/* Compressor forward(old_addr) -> new (to-space) address, via the offset
 * vector (one encoded transducer state per 512-byte block) and a scan of the
 * block's start/end mark bits.  Mirrors ForwardingMetadata::forward. */
static __always_inline unsigned long compressor_forward(unsigned long old)
{
	unsigned long block_start = old & ~511UL;
	__u64 offval = 0, markbits = 0;
	unsigned long to;
	unsigned int in_object, limit, last = 0, i;

	/* offset vector: 8-byte value at offvec_base + ((old>>9)<<3) */
	if (bpf_probe_read_user(&offval, sizeof(offval),
				(void *)(offvec_base + ((old >> 9) << 3))))
		return old;
	to = offval & ~1ULL;
	in_object = (unsigned int)(offval & 1ULL);

	/* the block's 64 start/end mark bits = 8 bytes at mark_base+(bs>>6) */
	if (bpf_probe_read_user(&markbits, sizeof(markbits),
				(void *)(mark_base + (block_start >> 6))))
		return old;

	limit = (unsigned int)((old - block_start) >> 3); /* words before old */
	for (i = 0; i < 64; i++) {
		if (i >= limit)
			break;
		if (markbits & (1ULL << i)) {
			if (in_object)
				to += (unsigned long)(i - last) * 8 + 8;
			in_object ^= 1u;
			last = i;
		}
	}
	return to;
}

struct fwd_ctx {
	unsigned char *page;
	unsigned long page_refbm;       /* refbm byte addr for slot 0 of page */
	__u64 refword;                  /* cached 64 reference bits */
};

/* Forward one 4-byte slot on the page if the reference bitmap marks it. */
static int fwd_slot(__u32 i, void *vctx)
{
	struct fwd_ctx *c = vctx;
	unsigned int off, idx;
	__u32 v, nv;
	unsigned long old, new;

	if (i >= PAGE_SIZE / 4)
		return 1;
	/* barrier so the compiler keeps the mask below (else it proves it
	 * redundant from the bound above and the verifier loses the bound). */
	barrier_var(i);
	idx = i & (PAGE_SIZE / 4 - 1);              /* 0..1023 */
	/* refill 64 reference bits at each group boundary (8 bytes / 64 slots) */
	if ((idx & 63) == 0 &&
	    bpf_probe_read_user(&c->refword, 8, (void *)(c->page_refbm + (idx >> 3))))
		return 0;
	if (!(c->refword & (1ULL << (idx & 63))))
		return 0;
	off = idx << 2;                             /* 0..4092, 4-aligned */
	v = *(__u32 *)(c->page + off);
	if (v == 0)
		return 0;
	old = coops_base + ((unsigned long)v << coops_shift);
	new = compressor_forward(old);
	nv = (__u32)((new - coops_base) >> coops_shift);
	*(__u32 *)(c->page + off) = nv;
	__sync_fetch_and_add(&b0_refs_forwarded, 1);
	return 0;
}

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
		if (!err && defer_fwd) {
			struct fwd_ctx c;
			unsigned long fa =
				ops_ctx->address & ~(unsigned long)(PAGE_SIZE - 1);

			c.page = page;
			/* byte address of this page's first 4-byte slot's ref bit */
			c.page_refbm = refbm_base + (((fa - space_base) >> 2) >> 3);
			bpf_loop(PAGE_SIZE / 4, fwd_slot, &c, 0);
		}
	} else if (st && *st == B0_PENDING) {
		err = -14; /* -EFAULT: bounce to userspace (SIGBUS steal) */
	}
	return err;
}

SEC(".struct_ops.link")
struct fault_ops gc_b0_ops = {
	.handle_page_fault = (void *)handle_page_fault,
};

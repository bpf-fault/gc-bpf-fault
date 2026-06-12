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

#define __arena __attribute__((address_space(1)))
#define arena_base(map) ((void __arena *)((struct bpf_arena *)(map))->user_vm_start)

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

/* BPF arena holding the forward table for DIRECT access (no probe_read).
 * Sized at load to cover span/2 bytes; userspace (the GC) writes the table
 * via the arena's mmap; this prog reads it via arena pointers. */
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1); /* resized to (span/2)/4096 before load */
	__ulong(map_extra, 1ull << 44);
} fwd_arena SEC(".maps");

#define B0_ZERO_FILL 0
#define B0_STAGED 1
#define B0_PENDING 2

const volatile unsigned long space_base = 0;
const volatile unsigned long arena_base = 0;
const volatile unsigned long span_len = 0;

/* Class B v2 forward params.  The forward table lives at BPF-arena offset 0;
 * the reference bitmap at arena offset refbm_off (set at init).  Both are read
 * directly via arena pointers -- no probe_read. */
unsigned long refbm_off = 0;     /* arena byte offset of the reference bitmap */
unsigned long coops_base = 0;    /* compressed-oops base (set after JVM init) */
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

struct fwd_ctx {
	unsigned char *page;
	unsigned long page_refbm;       /* refbm byte addr for slot 0 of page */
};

#define SLOTS_PER_PAGE (PAGE_SIZE / 4)   /* 1024 */
#define REFWORDS_PER_PAGE (SLOTS_PER_PAGE / 64) /* 16 */

/* Forward all reference slots in one 64-slot group (one bpf_loop iteration,
 * so dispatch is 16/page not 1024/page).  The forward is a direct arena
 * lookup, so the inner 64-bit loop stays simple for the verifier. */
static int fwd_word(__u32 w, void *vctx)
{
	struct fwd_ctx *c = vctx;
	__u8 __arena *arena = (__u8 __arena *)arena_base(&fwd_arena);
	__u32 __arena *table = (__u32 __arena *)arena;
	__u64 rw;
	int b;

	if (w >= REFWORDS_PER_PAGE)
		return 1;
	/* reference bits, read directly from the arena (no probe_read) */
	rw = *(__u64 __arena *)(arena + c->page_refbm + (w << 3));
	if (rw == 0)
		return 0;                           /* no references in this group */
	for (b = 0; b < 64; b++) {
		unsigned int off;
		__u32 v, nv;
		unsigned long old;

		if (!(rw & (1ULL << b)))
			continue;
		off = ((w << 6) | b) << 2;          /* slot (w*64+b) * 4 */
		barrier_var(off);
		off &= (PAGE_SIZE - 4);             /* bound to 0..4092 for verifier */
		v = *(__u32 *)(c->page + off);
		if (v == 0)
			continue;
		old = coops_base + ((unsigned long)v << coops_shift);
		if (old < space_base || old - space_base >= span_len)
			continue;                   /* not a compressor-space ref */
		nv = table[(old - space_base) >> 3];
		if (nv == 0)
			continue;                   /* no live forward: leave as-is */
		*(__u32 *)(c->page + off) = nv;
		__sync_fetch_and_add(&b0_refs_forwarded, 1);
	}
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
			/* arena byte offset of this page's first slot's ref bit */
			c.page_refbm = refbm_off + (((fa - space_base) >> 2) >> 3);
			bpf_loop(REFWORDS_PER_PAGE, fwd_word, &c, 0);
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

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
/* R1 (full in-kernel compaction) params */
unsigned long livebm_off = 0;    /* arena byte offset of the live-word bitmap */
unsigned long firstsrc_off = 0;  /* arena byte offset of the per-page first-src index */
unsigned int  inkernel = 0;      /* 1 = build pages from un-slid from-space */

volatile __u64 b0_fault_count = 0;
volatile __u64 b0_staged_installs = 0;
volatile __u64 b0_refs_forwarded = 0;
volatile __u64 b0_compact_words = 0;
volatile __u64 b0_prefail = 0;
volatile __u64 dbg_off = 0, dbg_srcw0 = 0, dbg_scratch0 = 0, dbg_live0 = 0, dbg_set = 0;
volatile __u64 dbg_w[8] = {};

#define R1_SCRATCH_WORDS 1024            /* 8 KiB from-space chunk / page */
struct r1_scratch { __u64 w[R1_SCRATCH_WORDS]; };
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct r1_scratch);
} r1_scratch_map SEC(".maps");

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

/* Forward one compressed-oop (narrow) value via the arena forward table.
 * Returns the new narrow value, or 0 for "leave unchanged" (null / out of the
 * compressor space / no live forward). */
static __always_inline __u32 forward_narrow(__u32 v)
{
	__u32 __arena *table = (__u32 __arena *)arena_base(&fwd_arena);
	unsigned long old;

	if (v == 0)
		return 0;
	old = coops_base + ((unsigned long)v << coops_shift);
	if (old < space_base || old - space_base >= span_len)
		return 0;
	return table[(old - space_base) >> 3];
}

#define R1_REGION_WORDS (1u << 17)       /* 1 MiB region / 8 bytes */

/* R1 compaction context: build one to-space page from un-slid from-space. */
struct r1_ctx {
	unsigned char *page;
	struct r1_scratch *s;
	__u32 srcw0;             /* from-space word index of scratch[0] */
	__u32 srcw;             /* next from-space word to inspect */
	__u32 outw;            /* live words emitted (0..512) */
	__u32 region_end;       /* stop here: the Compressor compacts per region */
	__u32 chunk;            /* words valid in scratch for this load */
	__u32 gbase0;           /* 64-aligned group base of this chunk's groups */
	__u32 total_words;      /* span_len >> 3 (chunk clamp) */
	/* slow path (page-boundary group) state, in memory so the per-bit
	 * callback carries no verifier-tracked register state */
	__u32 gcur;              /* group base of the group being emitted */
	__u64 lw, rb0, rb1;      /* the group's live and reference bits */
};

/* Groups per chunk: a page-sized chunk (512 words) plus first-chunk
 * misalignment spans at most 9 64-word live-bitmap groups. */
#define R1_GROUPS_PER_CHUNK 9

/* Forward the reference dwords of one emitted 64-bit word in place.
 * Successful forwards are counted straight into the global (a memory
 * side effect, like fwd_word) — a register accumulator here would be
 * loop-carried state that defeats verifier pruning in the caller. */
static __always_inline __u64 fwd_refs_in_word(__u64 word, __u64 rbits2)
{
	int h;

	for (h = 0; h < 2; h++) {
		__u32 v, nv;

		if (!(rbits2 & (1ULL << h)))
			continue;
		v = (h == 0) ? (__u32)word : (__u32)(word >> 32);
		nv = forward_narrow(v);
		if (nv == 0)
			continue;
		if (h == 0)
			word = (word & ~0xffffffffULL) | nv;
		else
			word = (word & 0xffffffffULL) | ((__u64)nv << 32);
		__sync_fetch_and_add(&b0_refs_forwarded, 1);
	}
	return word;
}

/* Slow path: emit one live word per call, used only for the (at most one
 * per fault) group that straddles the page-full boundary.  Loop-carried
 * state (outw/srcw) lives in the ctx STRUCT, which the verifier havocs
 * per callback — no cross-iteration register state, no explosion. */
static int emit_bit(__u32 b, void *vctx)
{
	struct r1_ctx *c = vctx;
	__u32 sidx, o;
	__u64 word, rbits2;

	if (!(c->lw & (1ULL << (b & 63))))
		return 0;
	if (c->outw >= PAGE_SIZE / 8) {
		/* page full: this bit resumes the next page's build */
		c->srcw = c->gcur + b;
		return 1;
	}
	sidx = c->gcur + b - c->srcw0;
	word = c->s->w[sidx & (R1_SCRATCH_WORDS - 1)];
	rbits2 = (b < 32 ? c->rb0 >> (2 * b) : c->rb1 >> (2 * (b & 31))) & 3;
	if (rbits2)
		word = fwd_refs_in_word(word, rbits2);
	o = c->outw & (PAGE_SIZE / 8 - 1);
	*(__u64 *)(c->page + o * 8) = word;
	c->outw++;
	__sync_fetch_and_add(&b0_compact_words, 1);
	return 0;
}

/* Emit one 64-word live-bitmap group per call (the compaction analogue of
 * fwd_word's 64-slot groups): a dead group is skipped with one u64 load; a
 * live group whose words all fit on the page is emitted by the FAST loop,
 * whose output offset is a PURE FUNCTION of the iteration —
 * outw0 + popcount(live bits below b) — so the loop carries no register
 * state and the verifier prunes it like fwd_word's.  (An `outw++`-style
 * accumulator differs on every live/dead path and explodes verification
 * to E2BIG; barrier_var does not help — it blinds clang, not the
 * verifier.)  The at-most-one group per fault that straddles the
 * page-full boundary takes the per-bit bpf_loop slow path instead. */
static int emit_group(__u32 g, void *vctx)
{
	struct r1_ctx *c = vctx;
	__u8 __arena *arena = (__u8 __arena *)arena_base(&fwd_arena);
	__u32 gbase = c->gbase0 + (g << 6);
	__u32 end = c->srcw0 + c->chunk;
	__u32 outw = c->outw;
	__u32 pc;
	__u64 lw, rb0, rb1;
	int b;

	if (end > c->region_end)
		end = c->region_end;
	if (gbase >= end)
		return 1;                /* chunk done: outer loop reloads */
	if (outw >= PAGE_SIZE / 8)
		return 1;                /* page full */
	/* live-word bitmap (arena, old positions), one whole group */
	lw = *(__u64 __arena *)(arena + livebm_off + (gbase >> 3));
	/* mask below the resume point (first group of a chunk only) and
	 * beyond the chunk/region end */
	if (c->srcw > gbase)
		lw &= ~0ULL << ((c->srcw - gbase) & 63);
	if (end - gbase < 64)
		lw &= (1ULL << ((end - gbase) & 63)) - 1;
	if (lw == 0) {
		c->srcw = gbase + 64 < end ? gbase + 64 : end;
		return 0;
	}
	pc = __builtin_popcountll(lw);
	if (outw + pc > PAGE_SIZE / 8) {
		/* page boundary inside this group: per-bit slow path */
		c->gcur = gbase;
		c->lw = lw;
		c->rb0 = *(__u64 __arena *)(arena + refbm_off + (gbase >> 2));
		c->rb1 = *(__u64 __arena *)(arena + refbm_off + (gbase >> 2) + 8);
		bpf_loop(64, emit_bit, c, 0);
		return 1;                /* page is now full */
	}
	/* the group's reference bits: slots [2*gbase, 2*gbase + 128) */
	rb0 = *(__u64 __arena *)(arena + refbm_off + (gbase >> 2));
	rb1 = *(__u64 __arena *)(arena + refbm_off + (gbase >> 2) + 8);
	if (lw == ~0ULL) {
		/* fully-live group (the common case in compacted data): the
		 * output offset is simply outw + b — no bit test, no popcount */
#pragma clang loop unroll(disable)
		for (b = 0; b < 64; b++) {
			__u32 sidx = gbase + b - c->srcw0;
			__u32 o = (outw + b) & (PAGE_SIZE / 8 - 1);
			__u64 word = c->s->w[sidx & (R1_SCRATCH_WORDS - 1)];
			__u64 rbits2 = (b < 32 ? rb0 >> (2 * b)
					      : rb1 >> (2 * (b & 31))) & 3;

			if (rbits2)
				word = fwd_refs_in_word(word, rbits2);
			*(__u64 *)(c->page + o * 8) = word;
		}
	} else {
#pragma clang loop unroll(disable)
	for (b = 0; b < 64; b++) {
		__u32 sidx, o;
		__u64 word, rbits2;

		if (!(lw & (1ULL << b)))
			continue;
		sidx = gbase + b - c->srcw0;
		word = c->s->w[sidx & (R1_SCRATCH_WORDS - 1)];
		rbits2 = (b < 32 ? rb0 >> (2 * b) : rb1 >> (2 * (b & 31))) & 3;
		if (rbits2)
			word = fwd_refs_in_word(word, rbits2);
		/* output offset as a pure function of (outw, lw, b) */
		o = (outw + __builtin_popcountll(lw & ((1ULL << b) - 1)))
			& (PAGE_SIZE / 8 - 1);
		*(__u64 *)(c->page + o * 8) = word;
	}
	}
	c->outw = outw + pc;
	c->srcw = gbase + 64 < end ? gbase + 64 : end;
	__sync_fetch_and_add(&b0_compact_words, pc);
	return c->outw >= PAGE_SIZE / 8 ? 1 : 0;
}

/* Load one from-space source page into scratch and emit its groups.  A
 * bpf_loop callback (rather than an open-coded loop in the handler) so the
 * verifier walks emit_group's callsite once, not once per chunk iteration
 * (open-coded 256x re-verification of the branchy group emit is E2BIG).
 * Each load stays within ONE from-space page: arena holes (dead heap pages
 * that were never materialized, so mremap moved nothing there) are
 * page-granular, and bpf_probe_read_user is all-or-nothing — a hole page
 * just means "nothing live here", skip it (any live word was written by
 * the mutator, so its page is mapped). */
static int load_and_emit_chunk(__u32 it, void *vctx)
{
	struct r1_ctx *c = vctx;
	__u32 wbase = c->srcw;
	__u32 chunk;

	if (c->outw >= PAGE_SIZE / 8 || wbase >= c->region_end)
		return 1;
	/* words from wbase to the end of its from-space page */
	chunk = (PAGE_SIZE / 8) - (wbase & (PAGE_SIZE / 8 - 1));
	if (wbase < c->total_words && c->total_words - wbase < chunk)
		chunk = c->total_words - wbase;
	barrier_var(chunk);
	if (chunk > R1_SCRATCH_WORDS)            /* bound the read size */
		chunk = R1_SCRATCH_WORDS;
	if (bpf_probe_read_user(c->s->w, (unsigned long)chunk * 8,
				(void *)(arena_base + (unsigned long)wbase * 8))) {
		/* hole: all-dead page, skip it */
		__sync_fetch_and_add(&b0_prefail, 1);
		c->srcw = wbase + chunk;
		return 0;
	}
	c->srcw0 = wbase;
	c->chunk = chunk;
	c->gbase0 = wbase & ~63u;
	bpf_loop(R1_GROUPS_PER_CHUNK, emit_group, c, 0);
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
	if (st && *st == B0_STAGED && inkernel) {
		/* R1: build the page from UN-SLID from-space (no userspace stage). */
		__u32 zero = 0, srcw0, total_words = span_len >> 3;
		__u32 __arena *fs_arena = (__u32 __arena *)((__u8 __arena *)arena_base(&fwd_arena) + firstsrc_off);
		struct r1_scratch *s = bpf_map_lookup_elem(&r1_scratch_map, &zero);
		struct r1_ctx c;

		__sync_fetch_and_add(&b0_staged_installs, 1);
		if (!s)
			return 0;
		srcw0 = fs_arena[idx];
		c.page = page;
		c.s = s;
		c.srcw = srcw0;
		c.outw = 0;
		/* region of srcw0 -> its global end word (compaction is per region) */
		c.region_end = ((srcw0 / R1_REGION_WORDS) + 1) * R1_REGION_WORDS;
		if (c.region_end > total_words)
			c.region_end = total_words;
		c.total_words = total_words;
		/* Build the page, reloading the scratch window (one source page
		 * per iteration) as needed: with sparse liveness one to-space
		 * page draws from far more than one chunk of from-space (up to
		 * the whole region). */
		bpf_loop(R1_REGION_WORDS / (PAGE_SIZE / 8), load_and_emit_chunk,
			 &c, 0);
		if (!dbg_set) {
			int j;
			dbg_off = off; dbg_srcw0 = srcw0;
			for (j = 0; j < 8; j++)
				dbg_w[j] = *(__u64 *)(page + j * 8);
			dbg_set = 1;
		}
		return 0;
	} else if (st && *st == B0_STAGED) {
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
		if (!dbg_set) {
			int j;
			dbg_off = off;
			for (j = 0; j < 8; j++)
				dbg_w[j] = *(__u64 *)(page + j * 8);
			dbg_set = 1;
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

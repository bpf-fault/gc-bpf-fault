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
volatile __u64 b0_prefail_live = 0; /* failed sub-reads with live bits (bad) */
volatile __u64 dbg_off = 0, dbg_srcw0 = 0, dbg_scratch0 = 0, dbg_live0 = 0, dbg_set = 0;
volatile __u64 dbg_w[8] = {};

#define R1_SCRATCH_WORDS 2048            /* 16 KiB from-space chunk / page */
/* Build state lives in the map value: map reads come back as unknown
 * scalars, so every bpf_loop pass sees one canonical state and verification
 * converges (stack-held ctx scalars creep per simulated iteration and blow
 * the 1M-insn budget).  Fields sit after w[] so chunk probe_reads cannot
 * clobber them.  cnt[i] = to-space word offset (prefix live count) at which
 * 64-word source chunk i of the current window starts emitting. */
#define R1_WIN_CHUNKS (R1_SCRATCH_WORDS / 64)
struct r1_scratch {
	__u64 w[R1_SCRATCH_WORDS];
	__u32 cnt[R1_WIN_CHUNKS];
	__u32 win;               /* window base (source word, 2048-aligned) */
	__u32 lo;                /* first source word to emit (first_src) */
	__u32 outw;              /* live words emitted so far (0..512) */
	__u32 region_end;        /* stop here: the Compressor compacts per region */
	__u32 nfwd;              /* refs forwarded (batched into the counter) */
};
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

/* may_goto-guarded loop condition (bpf_experimental.h `can_loop`): the
 * verifier bounds the loop via the may_goto iteration budget and prunes
 * states at the back-edge instead of unrolling -- the only loop form that
 * survives verification for the word-granular emit loop below (static
 * unrolls and bpf_loop callbacks both blow the 1M-insn budget; open-coded
 * iterators fail to converge on the loop-carried bounds). */
#define can_loop					\
	({ __label__ l_break, l_continue;		\
	int __ret = 1;					\
	asm volatile goto("may_goto %l[l_break]"	\
			  :::: l_break);		\
	goto l_continue;				\
	l_break: __ret = 0;				\
	l_continue:;					\
	__ret;						\
	})


/* R1 page build, structured for the BPF verifier.  A page build walks the
 * live-word bitmap from the page's first_src, copies live words compactly,
 * and forwards flagged reference dwords.  The naive forms all fail
 * verification or run slow: a per-word bpf_loop verifies but pays an
 * indirect call per source word (~190K page builds per window made that the
 * dominant window cost); wider callback bodies with a carried output cursor
 * never converge (the cursor's creeping bounds defeat state pruning) and
 * blow the 1M-insn budget, with static loops, open-coded iterators, and
 * may_goto alike.  The fix is fwd_word's shape: 64-iteration branchy
 * callbacks verify fine when each iteration's output position is
 * INDEPENDENT of the previous ones.  So phase A computes each 64-word
 * chunk's output offset as a branch-free popcount prefix (linear to
 * verify), and phase B emits each chunk at its precomputed offset with no
 * cross-callback state.  ~65 dispatches per page instead of ~2000. */
struct r1_ctx {
	unsigned char *page;
	struct r1_scratch *s;
};

/* Phase A: cnt[i] = output offset of chunk i (prefix live count).  Branch-
 * free popcount body -- verification is linear, the carried prefix lives in
 * the map. */
static int r1_count_step(__u32 i, void *vctx)
{
	struct r1_ctx *c = vctx;
	struct r1_scratch *s = c->s;
	__u8 __arena *arena = (__u8 __arena *)arena_base(&fwd_arena);
	__u32 w0 = s->win + (i << 6), lo = s->lo, re = s->region_end;
	__u64 bits;

	if (i >= R1_WIN_CHUNKS)
		return 1;
	bits = *(__u64 __arena *)(arena + livebm_off + ((w0 >> 3) & ~7u));
	/* mask words before first_src and at/after region_end */
	if (w0 < lo)
		bits &= (lo - w0 < 64) ? (~0ULL << (lo - w0)) : 0;
	if (re - w0 < 64)
		bits &= (1ULL << (re - w0)) - 1;
	if (w0 >= re)
		bits = 0;
	s->cnt[i & (R1_WIN_CHUNKS - 1)] = s->outw;
	/* branch-free popcount64 */
	bits = bits - ((bits >> 1) & 0x5555555555555555ULL);
	bits = (bits & 0x3333333333333333ULL) + ((bits >> 2) & 0x3333333333333333ULL);
	bits = (bits + (bits >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
	s->outw += (__u32)((bits * 0x0101010101010101ULL) >> 56);
	return 0;
}

/* Phase B: emit chunk i at its precomputed offset.  No cross-callback
 * state: out position derives from cnt[i] alone, so states converge (same
 * shape as fwd_word). */
static int r1_emit_step(__u32 i, void *vctx)
{
	struct r1_ctx *c = vctx;
	struct r1_scratch *s = c->s;
	__u8 __arena *arena = (__u8 __arena *)arena_base(&fwd_arena);
	__u32 w0 = s->win + (i << 6), lo = s->lo, re = s->region_end;
	__u32 out;
	__u64 bits;
	int j;

	if (i >= R1_WIN_CHUNKS)
		return 1;
	out = s->cnt[i & (R1_WIN_CHUNKS - 1)];
	if (out >= PAGE_SIZE / 8)
		return 1;                            /* page already full */
	bits = *(__u64 __arena *)(arena + livebm_off + ((w0 >> 3) & ~7u));
	if (w0 < lo)
		bits &= (lo - w0 < 64) ? (~0ULL << (lo - w0)) : 0;
	if (re - w0 < 64)
		bits &= (1ULL << (re - w0)) - 1;
	if (w0 >= re)
		bits = 0;
	/* No carried accumulators in registers: a concrete running output
	 * count (or ref count) gives every loop iteration a distinct
	 * verifier state and verification explodes 100x past the 1M-insn
	 * budget.  Each word derives its output slot from a branch-free
	 * popcount of the live bits BELOW it -- symbolic, so the per-j
	 * states converge.  Ref counting goes straight to the map. */
	for (j = 0; j < 64; j++) {
		__u64 word, below;
		__u32 pos;
		int h;

		if (!(bits & (1ULL << j)))
			continue;
		below = bits & ((1ULL << j) - 1);
		below = below - ((below >> 1) & 0x5555555555555555ULL);
		below = (below & 0x3333333333333333ULL) +
			((below >> 2) & 0x3333333333333333ULL);
		below = (below + (below >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
		pos = out + (__u32)((below * 0x0101010101010101ULL) >> 56);
		if (pos >= PAGE_SIZE / 8)
			break;                       /* page full mid-chunk */
		word = s->w[((i << 6) + j) & (R1_SCRATCH_WORDS - 1)];
		/* forward the two 4-byte reference dwords flagged in the
		 * (old) refbitmap */
		for (h = 0; h < 2; h++) {
			__u32 slot = ((w0 + j) << 1) | h;
			__u32 v, nv;

			if (!(*(__u8 __arena *)(arena + refbm_off + (slot >> 3)) & (1u << (slot & 7))))
				continue;
			v = (h == 0) ? (__u32)word : (__u32)(word >> 32);
			nv = forward_narrow(v);
			if (nv == 0)
				continue;
			if (h == 0)
				word = (word & ~0xffffffffULL) | nv;
			else
				word = (word & 0xffffffffULL) | ((__u64)nv << 32);
			s->nfwd += 1;
		}
		*(__u64 *)(c->page + (pos & (PAGE_SIZE / 8 - 1)) * 8) = word;
	}
	return 0;
}

/* One source window: load scratch (page-aligned reads; a straddling read
 * would fail as a unit on a hole and lose the live resident half), count,
 * emit, advance. */
static int r1_window_step(__u32 index, void *vctx)
{
	struct r1_ctx *c = vctx;
	struct r1_scratch *s = c->s;
	__u32 win = s->win, chunk, half;

	if (s->outw >= PAGE_SIZE / 8 || win >= s->region_end)
		return 1;
	chunk = R1_SCRATCH_WORDS;
	if (s->region_end - win < chunk)
		chunk = s->region_end - win;
	barrier_var(chunk);
	if (chunk > R1_SCRATCH_WORDS)
		chunk = R1_SCRATCH_WORDS;
	if (bpf_probe_read_user(s->w, (unsigned long)chunk * 8,
				(void *)(arena_base + (unsigned long)win * 8))) {
		/* Sparse alias: retry per page; a failing page holds no live
		 * words (live data is resident -- swap off) and only live
		 * words are read, so no zeroing.  livehit is the alarm. */
		half = 0;
		while (half < chunk && can_loop) {
			if (bpf_probe_read_user(&s->w[half & (R1_SCRATCH_WORDS - 1)],
						512 * 8,
						(void *)(arena_base +
							 (unsigned long)(win + half) * 8))) {
				__u8 __arena *lb = (__u8 __arena *)arena_base(&fwd_arena) + livebm_off;
				__u32 wf = win + half, j, livehit = 0;

				for (j = 0; j < 64; j++)
					livehit |= *(volatile __u8 __arena *)(lb + (wf >> 3) + j);
				__sync_fetch_and_add(&b0_prefail, 1);
				if (livehit)
					__sync_fetch_and_add(&b0_prefail_live, 1);
			}
			half += 512;
		}
	}
	bpf_loop(R1_WIN_CHUNKS, r1_count_step, c, 0);
	bpf_loop(R1_WIN_CHUNKS, r1_emit_step, c, 0);
	s->win = win + R1_SCRATCH_WORDS;
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
		__u32 zero = 0, srcw0, region_end, total_words = span_len >> 3;
		__u32 __arena *fs_arena = (__u32 __arena *)((__u8 __arena *)arena_base(&fwd_arena) + firstsrc_off);
		struct r1_scratch *s = bpf_map_lookup_elem(&r1_scratch_map, &zero);

		__sync_fetch_and_add(&b0_staged_installs, 1);
		if (!s)
			return 0;
		srcw0 = fs_arena[idx];
		/* region of srcw0 -> its global end word (compaction is per region) */
		region_end = ((srcw0 / R1_REGION_WORDS) + 1) * R1_REGION_WORDS;
		if (region_end > total_words)
			region_end = total_words;
		{
			struct r1_ctx c = { .page = page, .s = s };

			s->lo = srcw0;
			/* window-aligned load base; the leading sub-window
			 * words are masked off via lo */
			s->win = srcw0 & ~(R1_SCRATCH_WORDS - 1);
			s->outw = 0;
			s->region_end = region_end;
			s->nfwd = 0;
			/* enough windows to cross a whole region if need be */
			bpf_loop(R1_REGION_WORDS / R1_SCRATCH_WORDS + 1,
				 r1_window_step, &c, 0);
			if (s->outw)
				__sync_fetch_and_add(&b0_compact_words,
						     s->outw > PAGE_SIZE / 8 ?
						     PAGE_SIZE / 8 : s->outw);
			if (s->nfwd)
				__sync_fetch_and_add(&b0_refs_forwarded, s->nfwd);
		}
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

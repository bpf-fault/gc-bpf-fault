// SPDX-License-Identifier: GPL-2.0-only
/*
 * Class B v2 CAPSTONE: full Compressor-style in-kernel materialization.
 *
 * Proves the remaining kernel pieces for live MMTk integration, all in the
 * missing-fault handler, arena-backed:
 *   - VARIABLE-SIZE objects (runs of live words), found via a live-word
 *     mark bitmap (no fixed object size).
 *   - forward() from an OFFSET VECTOR (cumulative live words per block) +
 *     mark-bitmap popcount — the Compressor's forwarding computation, not a
 *     flat table.
 *   - a per-to-space-page FIRST-SOURCE-WORD index so the handler knows where
 *     to start scanning from-space for a randomly-faulted page.
 *   - a REFERENCE BITMAP (1 bit/word) identifying pointer words to forward.
 *
 * Layout: the heap is an array of u64 words.  A live object occupies a run
 * of consecutive live words (livebits set); compaction removes dead gaps and
 * slides live words together, preserving object runs.  forward(old_word) =
 * to_base + (live words before old_word) * 8.  References hold a 1-based old
 * word index of a referent object's first word.
 *
 * clang>=19 (native addr_space_cast).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";
#define __arena __attribute__((address_space(1)))
#define __arena_global __attribute__((address_space(1)))

#define PAGE_SIZE   4096
#define PAGE_SHIFT  12
#define WORDS_PER_PAGE (PAGE_SIZE / 8)        /* 512 */
#define BLOCK_WORDS 64                        /* offset-vector granularity */
#define MAX_WORDS   (1u << 24)                /* 16M words = 128MB heap cap */

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1u << 16);            /* 256MB arena */
	__ulong(map_extra, 0x1ull << 44);
} arena SEC(".maps");

__u64 __arena_global from_space[MAX_WORDS];                 /* old heap words */
__u64 __arena_global livebits[MAX_WORDS / 64];              /* 1 = live word */
__u64 __arena_global refbits[MAX_WORDS / 64];               /* 1 = reference */
__u32 __arena_global offvec[MAX_WORDS / BLOCK_WORDS];       /* cumulative live words before block */
__u32 __arena_global first_src[MAX_WORDS / WORDS_PER_PAGE]; /* per to-page: 0-based first live src word */

const volatile unsigned long to_base = 0;
const volatile unsigned long span_len = 0;
const volatile unsigned int  nr_live_words = 0;   /* total live words (= to-space words) */
const volatile unsigned int  total_words = 0;

volatile __u64 kc_faults = 0;
volatile __u64 kc_words = 0;
volatile __u64 kc_refs = 0;

/* forward(old 0-based word index) -> new ADDRESS. */
static __always_inline __u64 forward_word(__u32 oldw)
{
	__u32 blk, base, bstart, i, cnt = 0;

	if (oldw >= total_words)
		return to_base;                   /* bogus ref: bound oldw */
	blk = oldw / BLOCK_WORDS;
	base = offvec[blk];                       /* live words before block */
	bstart = blk * BLOCK_WORDS;

	/* live words in [bstart, oldw); fixed 64-iteration bound. */
	for (i = 0; i < BLOCK_WORDS; i++) {
		__u32 w = bstart + i;

		if (w >= oldw)
			break;
		if (livebits[w >> 6] & (1ULL << (w & 63)))
			cnt++;
	}
	return to_base + (__u64)(base + cnt) * 8;
}

/* bpf_loop context: stateful scan cursor over from-space for one page. */
struct kctx {
	unsigned char *page;
	__u32 srcw;       /* next from-space word to inspect */
	__u32 outw;       /* live words emitted so far (0..512) */
};

/* Emit at most one live word per call; srcw advances every call, outw only on
 * a live word.  Returns 1 to stop the loop (page full / heap exhausted). */
static int emit_word(__u32 index, void *ctx_)
{
	struct kctx *c = ctx_;
	__u32 srcw = c->srcw;
	__u32 outw = c->outw;
	__u64 word;

	if (outw >= WORDS_PER_PAGE || srcw >= total_words)
		return 1;
	c->srcw = srcw + 1;
	if (!(livebits[srcw >> 6] & (1ULL << (srcw & 63))))
		return 0;                         /* dead word: skip */
	word = from_space[srcw];
	if (refbits[srcw >> 6] & (1ULL << (srcw & 63))) {
		if (word != 0)
			word = forward_word((__u32)word - 1); /* 1-based -> addr */
		__sync_fetch_and_add(&kc_refs, 1);
	}
	outw &= (WORDS_PER_PAGE - 1);             /* tell verifier outw < 512 */
	*(__u64 *)(c->page + outw * 8) = word;
	c->outw = outw + 1;
	__sync_fetch_and_add(&kc_words, 1);
	return 0;
}

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *octx,
	     unsigned char *page)
{
	unsigned long off = octx->address - to_base;
	struct kctx c;

	__sync_fetch_and_add(&kc_faults, 1);
	if (off >= span_len)
		return 0;

	c.page = page;
	c.srcw = first_src[off >> PAGE_SHIFT];     /* first live src word for page */
	c.outw = 0;

	/* Scan from-space, compacting live words into the page.  bpf_loop keeps
	 * the verifier happy with a large bound; emit_word breaks early. */
	bpf_loop(WORDS_PER_PAGE * 8, emit_word, &c, 0);
	return 0;
}

SEC(".struct_ops.link")
struct fault_ops gc_kompress = {
	.handle_page_fault = (void *)handle_page_fault,
};

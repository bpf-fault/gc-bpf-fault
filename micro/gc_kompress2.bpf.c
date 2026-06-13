// SPDX-License-Identifier: GPL-2.0-only
/*
 * R1 de-risk: in-kernel compaction reading UN-SLID from-space via probe_read.
 *
 * gc_kompress proved in-kernel compaction with from-space in the BPF arena
 * (direct access).  In the real GC, from-space is the mremap'd heap (a regular
 * VMA), so the handler must bulk-probe_read a source range into a scratch, then
 * compact out of it.  This isolates that delta: from-space is a plain mmap
 * (from_base); metadata (livebits/refbits/fwd/first_src) is in the arena; each
 * to-space page is built by reading one ~8 KiB from-space chunk into a per-cpu
 * scratch and emitting its live words, forwarding refs via a flat table (the
 * representation the real integration uses -- not an offset-vector scan).
 *
 * (One chunk per page assumes >=50% live so 512 live words fit in 1024 source
 * words; the real handler reloads chunks for sparser regions.)
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
#define MAX_WORDS   (1u << 24)
#define SCRATCH_WORDS 4096                    /* 8 KiB from-space chunk / page */

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1u << 16);
	__ulong(map_extra, 0x1ull << 44);
} arena SEC(".maps");

/* metadata in the arena (direct access) */
__u64 __arena_global livebits[MAX_WORDS / 64];
__u64 __arena_global refbits[MAX_WORDS / 64];
__u64 __arena_global fwd[MAX_WORDS];                       /* old word -> new addr */
__u32 __arena_global first_src[MAX_WORDS / WORDS_PER_PAGE];

/* per-cpu scratch for the probe_read'd from-space chunk */
struct scratch { __u64 w[SCRATCH_WORDS]; };
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} scratch_map SEC(".maps");

const volatile unsigned long to_base = 0;
const volatile unsigned long from_base = 0;   /* un-slid from-space (mmap) */
const volatile unsigned long span_len = 0;
const volatile unsigned int  total_words = 0;

volatile __u64 kc_faults = 0;
volatile __u64 kc_words = 0;
volatile __u64 kc_refs = 0;
volatile __u64 kc_prefail = 0;
volatile __u64 kc_chunkfull = 0;

struct kctx {
	unsigned char *page;
	struct scratch *s;
	__u32 srcw0;
	__u32 srcw;
	__u32 outw;
};

static int emit_word(__u32 index, void *ctx_)
{
	struct kctx *c = ctx_;
	__u32 srcw = c->srcw;
	__u32 outw = c->outw;
	__u32 sidx;
	__u64 word;

	if (outw >= WORDS_PER_PAGE || srcw >= total_words)
		return 1;
	c->srcw = srcw + 1;
	if (!(livebits[srcw >> 6] & (1ULL << (srcw & 63))))
		return 0;                         /* dead word */
	sidx = srcw - c->srcw0;
	if (sidx >= SCRATCH_WORDS) {
		__sync_fetch_and_add(&kc_chunkfull, 1);
		return 1;                         /* chunk exhausted (would reload) */
	}
	word = c->s->w[sidx];
	if (refbits[srcw >> 6] & (1ULL << (srcw & 63))) {
		if (word != 0)
			word = fwd[(__u32)word - 1];  /* flat forward table */
		__sync_fetch_and_add(&kc_refs, 1);
	}
	outw &= (WORDS_PER_PAGE - 1);
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
	__u32 zero = 0, srcw0;
	struct scratch *s;

	__sync_fetch_and_add(&kc_faults, 1);
	if (off >= span_len)
		return 0;

	s = bpf_map_lookup_elem(&scratch_map, &zero);
	if (!s)
		return 0;
	srcw0 = first_src[off >> PAGE_SHIFT];
	if (bpf_probe_read_user(s->w, sizeof(s->w),
				(void *)(from_base + (unsigned long)srcw0 * 8))) {
		__sync_fetch_and_add(&kc_prefail, 1);
		return 0;
	}

	c.page = page;
	c.s = s;
	c.srcw0 = srcw0;
	c.srcw = srcw0;
	c.outw = 0;
	bpf_loop(WORDS_PER_PAGE * 8, emit_word, &c, 0);
	return 0;
}

SEC(".struct_ops.link")
struct fault_ops gc_kompress2 = {
	.handle_page_fault = (void *)handle_page_fault,
};

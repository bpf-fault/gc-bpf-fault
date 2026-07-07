// SPDX-License-Identifier: GPL-2.0-only
/*
 * Compressed cold heap: missing-fault handler that DECOMPRESSES the page
 * in-kernel from a compressed store.  The GC compresses cold pages in
 * userspace and unmaps the originals; the first access materializes the
 * page via this handler (~one decode, no signal, no userspace
 * round-trip).  userfaultfd would pay a 30-50us handler round-trip per
 * page plus a userspace decode; the bpf path is fault + in-kernel decode.
 *
 * v1 codec: zero-suppression (heap pages are zero-heavy).  Per page:
 *   [u16 prefix[8]]  payload word-count before each 64-word group
 *   [u64 tags[8]]    bit=1: word is present in payload; 0: word is zero
 *   [u64 payload[]]  the nonzero words, in order
 * The decoder computes each word's payload index as
 * prefix[group] + popcount(tag & below(bit)) — a pure function of the
 * iteration, so the verifier state stays linear (no loop-carried
 * accumulator; the emit_group lesson).
 *
 * Offset table (arena): u32 byte offset of each page's compressed image
 * (0xffffffff = not compressed -> zero-fill).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define __arena __attribute__((address_space(1)))
#define arena_base(map) ((void __arena *)((struct bpf_arena *)(map))->user_vm_start)

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

const volatile unsigned long heap_base = 0;
const volatile unsigned long span_len = 0;
unsigned long offtab_off = 0;    /* arena byte offset of the offset table */
unsigned long zflags_off = 0;    /* arena byte offset of decompressed flags */

volatile __u64 z_faults = 0;
volatile __u64 z_decoded = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1); /* resized before load */
	__ulong(map_extra, 1ull << 46);
} z_arena SEC(".maps");

struct z_ctx {
	unsigned char *page;
	__u8 __arena *img;       /* compressed image base */
};

/* Decode one 64-word group: one tag load, popcount-indexed payload. */
static int z_group(__u32 g, void *vctx)
{
	struct z_ctx *c = vctx;
	__u16 __arena *prefix = (__u16 __arena *)c->img;
	__u64 __arena *tags = (__u64 __arena *)(c->img + 16);
	__u64 __arena *payload = (__u64 __arena *)(c->img + 16 + 64);
	__u64 tag;
	__u32 base;
	int b;

	if (g >= 8)
		return 1;
	tag = tags[g & 7];
	base = prefix[g & 7];
#pragma clang loop unroll(disable)
	for (b = 0; b < 64; b++) {
		__u32 o = ((g & 7) << 6) | b;
		__u64 w = 0;

		if (tag & (1ULL << b)) {
			__u32 pi = base + (__u32)__builtin_popcountll(tag & ((1ULL << b) - 1));
			w = payload[pi & 511];
		}
		*(__u64 *)(c->page + ((o & 511) << 3)) = w;
	}
	return 0;
}

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *page)
{
	__u8 __arena *arena = (__u8 __arena *)arena_base(&z_arena);
	unsigned long off = ops_ctx->address - heap_base;
	__u32 idx, img_off;
	struct z_ctx c;

	__sync_fetch_and_add(&z_faults, 1);
	if (off >= span_len)
		return 0;
	idx = off >> PAGE_SHIFT;
	img_off = *(__u32 __arena *)(arena + offtab_off + ((unsigned long)idx << 2));
	if (img_off == 0xffffffff)
		return 0;            /* not compressed: zero-fill */
	c.page = page;
	c.img = arena + img_off;
	bpf_loop(8, z_group, &c, 0);
	__sync_fetch_and_add(&z_decoded, 1);
	/* tell userspace this page is hot again (GC clears per cycle) */
	if (zflags_off)
		*(__u8 __arena *)(arena + zflags_off + idx) = 1;
	return 0;
}

SEC(".struct_ops.link")
struct fault_ops gc_z_ops = {
	.handle_page_fault = (void *)handle_page_fault,
};

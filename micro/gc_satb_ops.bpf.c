// SPDX-License-Identifier: GPL-2.0-only
/*
 * Page-COW SATB: write-protect fault handler that snapshots the PRE-WRITE
 * page content into a BPF arena before allowing the write.
 *
 * This is the mechanism for virtual-memory-based concurrent marking:
 * arm the heap with WP at mark start; the first write to any page copies
 * its mark-start content into the snapshot arena in-kernel (~one page
 * copy, no signal, no userspace round-trip) and clears the protection.
 * A concurrent SATB drainer scans snapshot pages for references, giving
 * snapshot-at-the-beginning completeness while the marker reads the live
 * heap.  userfaultfd-WP would pay a userspace handler round-trip per
 * snapshot; the compiled-barrier equivalent (SATB card/logging barriers)
 * costs on every reference store instead of once per page.
 *
 * Arena layout: [ snapshot pages (span) | snap bitmap (span/PAGE/8) ].
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern int bpf_fault_writeprotect(struct bpf_fault_ops_ctx *ctx,
				  __u64 start, __u64 len, bool enable_wp) __ksym;

#define __arena __attribute__((address_space(1)))
#define arena_base(map) ((void __arena *)((struct bpf_arena *)(map))->user_vm_start)

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

const volatile unsigned long heap_base = 0;
const volatile unsigned long span_len = 0;

unsigned long snapbm_off = 0;    /* arena byte offset of the snap bitmap */
volatile __u64 satb_snapshots = 0;
volatile __u64 satb_read_fail = 0;
volatile __u32 satb_count = 0;   /* debug counters opt-in */
volatile __u32 satb_noop = 0;    /* bisect: WP fault -> immediate return */
volatile __u32 satb_prefetch = 0; /* snapshot+unprotect next pages per fault */
volatile __u64 satb_dropped = 0; /* arena read-back verify failures */

struct comm_key { char comm[16]; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct comm_key);
	__type(value, __u64);
} satb_comms SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1); /* resized before load */
	__ulong(map_extra, 1ull << 45);
} snap_arena SEC(".maps");

/* probe_read_user cannot target arena memory (verifier); bounce through a
 * per-CPU scratch page.  (An arena-dst probe_read variant would save one
 * page copy per snapshot -- minor kernel-gap item.) */
struct satb_scratch { __u64 w[PAGE_SIZE / 8]; };
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct satb_scratch);
} satb_scratch_map SEC(".maps");

SEC("struct_ops.s/handle_wp_fault")
int BPF_PROG(handle_wp_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *page)
{
	__u8 __arena *arena = (__u8 __arena *)arena_base(&snap_arena);
	unsigned long off = ops_ctx->address - heap_base;
	unsigned long idx, pa;

	{
		/* who writes armed pages? (finding the pause-context writer) */
		struct comm_key k = {};
		__u64 one = 1, *v;

		bpf_get_current_comm(k.comm, sizeof(k.comm));
		v = bpf_map_lookup_elem(&satb_comms, &k);
		if (v)
			__sync_fetch_and_add(v, 1);
		else
			bpf_map_update_elem(&satb_comms, &k, &one, BPF_ANY);
	}
	if (satb_noop)
		return 0;      /* isolate kernel WP mechanics from handler work */
	if (off >= span_len)
		return 0;
	idx = off >> PAGE_SHIFT;
	/* One snapshot per page per mark cycle; the flag doubles as the
	 * "drain me" marker for the userspace SATB drainer.  BYTE-per-page
	 * (not a bitmap): arena atomics are not allowed, and a plain store
	 * to your own byte cannot clobber neighbouring pages' flags.  A
	 * same-page fault race just snapshots the same pre-write content
	 * twice -- idempotent. */
	if (*(__u8 __arena *)(arena + snapbm_off + idx))
		return 0;                      /* already snapshotted */
	pa = ops_ctx->address & ~(unsigned long)(PAGE_SIZE - 1);
	/* copy the PRE-WRITE content: the fault fires before the store */
	{
		__u32 zero = 0;
		struct satb_scratch *s = bpf_map_lookup_elem(&satb_scratch_map, &zero);
		__u64 __arena *dst = (__u64 __arena *)(arena + (idx << PAGE_SHIFT));
		int i;

		if (!s)
			return 0;
		if (bpf_probe_read_user(s->w, PAGE_SIZE, (void *)pa)) {
			if (satb_count)
				__sync_fetch_and_add(&satb_read_fail, 1);
			return 0;      /* let the write proceed regardless */
		}
		for (i = 0; i < PAGE_SIZE / 8; i++)
			dst[i] = s->w[i];
		/* read-back verify: kernel stores to unpopulated arena pages
		 * are dropped silently (exception fixups); detect in vivo. */
		if (dst[0] != s->w[0] || dst[255] != s->w[255] ||
		    dst[511] != s->w[511])
			__sync_fetch_and_add(&satb_dropped, 1);
	}
	*(__u8 __arena *)(arena + snapbm_off + idx) = 1;
	if (satb_count)
		__sync_fetch_and_add(&satb_snapshots, 1);
	/* PREFETCH: sequential writers fault page-after-page (~9us each).
	 * Snapshot the next 3 pages too and bulk-resolve their WP --
	 * snapshot-before-unprotect keeps SATB exact; random writers just
	 * waste <=3 page copies (~2us each). */
	if (satb_prefetch) {
		unsigned long k, kidx, kpa;
		__u32 zero = 0;
		struct satb_scratch *s2;
		int done = 0;

		for (k = 1; k <= 3; k++) {
			kpa = pa + (k << PAGE_SHIFT);
			kidx = idx + k;
			if (kpa - heap_base >= span_len)
				break;
			if (*(__u8 __arena *)(arena + snapbm_off + kidx))
				break;          /* already snapshotted */
			s2 = bpf_map_lookup_elem(&satb_scratch_map, &zero);
			if (!s2)
				break;
			if (bpf_probe_read_user(s2->w, PAGE_SIZE, (void *)kpa))
				break;          /* unmapped/unarmed: stop */
			{
				__u64 __arena *d2 =
					(__u64 __arena *)(arena + (kidx << PAGE_SHIFT));
				int i;

				for (i = 0; i < PAGE_SIZE / 8; i++)
					d2[i] = s2->w[i];
			}
			*(__u8 __arena *)(arena + snapbm_off + kidx) = 1;
			done = k;
		}
		if (done)
			bpf_fault_writeprotect(ops_ctx, pa + PAGE_SIZE,
					       (unsigned long)done << PAGE_SHIFT,
					       false);
	}
	return 0;
}

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *page)
{
	return 0;              /* WP-only registration */
}

SEC(".struct_ops.link")
struct fault_ops gc_satb_ops = {
	.handle_page_fault = (void *)handle_page_fault,
	.handle_wp_fault = (void *)handle_wp_fault,
};

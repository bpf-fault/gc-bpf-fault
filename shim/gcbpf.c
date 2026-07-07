// SPDX-License-Identifier: GPL-2.0-only
/*
 * C shim exposing bpf_fault WP dirty tracking to MMTk (dlopen'ed by
 * mmtk-core's dirty_track module).  Wraps skeleton load/attach, multi-region
 * registration, range write-protect, and the mmaped dirty bitmap.
 *
 * The eBPF program (gc_wp_ops.bpf.c, shared with micro/) sets a bit in the
 * dirty bitmap on each WP fault and allows the write.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_wp_ops.skel.h"
#include "../micro/gc_common.h"

static struct gc_wp_ops_bpf *skel;
static struct bpf_link *wp_link;
static uint64_t *bitmap;
static unsigned long span_start;
static unsigned long span_len;

int gcbpf_init(uint64_t start, uint64_t len)
{
	size_t words = (len / 4096 + 63) / 64;
	size_t map_bytes;
	long page = sysconf(_SC_PAGESIZE);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = gc_wp_ops_bpf__open();
	if (!skel) {
		fprintf(stderr, "gcbpf: open skeleton failed\n");
		return -1;
	}
	skel->rodata->heap_base = start;
	if (bpf_map__set_max_entries(skel->maps.dirty_bitmap, words)) {
		fprintf(stderr, "gcbpf: set_max_entries failed\n");
		return -1;
	}
	if (gc_wp_ops_bpf__load(skel)) {
		fprintf(stderr, "gcbpf: load failed (need CAP_BPF / root)\n");
		return -1;
	}

	map_bytes = (words * sizeof(uint64_t) + page - 1) & ~(page - 1);
	bitmap = mmap(NULL, map_bytes, PROT_READ | PROT_WRITE, MAP_SHARED,
		      bpf_map__fd(skel->maps.dirty_bitmap), 0);
	if (bitmap == MAP_FAILED) {
		perror("gcbpf: mmap dirty_bitmap");
		bitmap = NULL;
		return -1;
	}

	span_start = start;
	span_len = len;
	return 0;
}

int gcbpf_register(uint64_t start, uint64_t len)
{
	if (!skel)
		return -1;
	if (!wp_link) {
		wp_link = bpf_map__attach_fault_ops(skel->maps.gc_wp_ops,
						 (void *)start, len,
						 BPF_FAULT_FLAG_WP);
		if (!wp_link) {
			perror("gcbpf: attach_fault_ops");
			return -1;
		}
		return 0;
	}
	if (bpf_link__fault_register(bpf_link__fd(wp_link), start, len)) {
		perror("gcbpf: fault_register");
		return -1;
	}
	return 0;
}

int gcbpf_wp(uint64_t start, uint64_t len, int enable)
{
	if (!wp_link)
		return -1;
	if (bpf_link_fault_cmd(bpf_link__fd(wp_link), start, len,
			       enable ? BPF_FAULT_WP_ENABLE : 0)) {
		perror("gcbpf: writeprotect");
		return -1;
	}
	return 0;
}

uint64_t *gcbpf_bitmap(void)
{
	return bitmap;
}

uint64_t gcbpf_fault_count(void)
{
	return skel ? skel->bss->wp_fault_count : 0;
}

/* ------------------------------------------------------------------ */
/*  SATB page snapshots: page-COW barrier for concurrent marking       */
/* ------------------------------------------------------------------ */

#include "gc_satb_ops.skel.h"

static struct gc_satb_ops_bpf *satb_skel;
static struct bpf_link *satb_link;
static uint8_t *satb_arena;        /* [snapshot pages | byte flags] */
static uint64_t satb_base, satb_span, satb_flags_off;

/* Load the snapshot handler and mmap+pre-touch the arena.  Pre-touching
 * is mandatory: kernel-side stores to unpopulated arena pages are
 * silently dropped (exception fixups).  The arena stays resident across
 * mark cycles (v1). */
int gcsatb_init(uint64_t start, uint64_t len)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t flags_bytes = len >> 12;
	size_t arena_bytes;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	satb_skel = gc_satb_ops_bpf__open();
	if (!satb_skel) {
		fprintf(stderr, "gcsatb: open failed\n");
		return -1;
	}
	satb_skel->rodata->heap_base = start;
	satb_skel->rodata->span_len = len;
	arena_bytes = (len + flags_bytes + page - 1) & ~(size_t)(page - 1);
	if (bpf_map__set_max_entries(satb_skel->maps.snap_arena,
				     arena_bytes / page)) {
		fprintf(stderr, "gcsatb: arena size failed\n");
		return -1;
	}
	if (gc_satb_ops_bpf__load(satb_skel)) {
		fprintf(stderr, "gcsatb: load failed (root?)\n");
		return -1;
	}
	satb_skel->bss->snapbm_off = len;
	{
		uint64_t va = 1ull << 45;
		satb_arena = mmap((void *)va, arena_bytes,
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED | MAP_FIXED,
				  bpf_map__fd(satb_skel->maps.snap_arena), 0);
		if (satb_arena == MAP_FAILED) {
			perror("gcsatb: mmap arena");
			satb_arena = NULL;
			return -1;
		}
	}
	for (size_t i = 0; i < arena_bytes; i += page)
		satb_arena[i] = 0;
	satb_base = start;
	satb_span = len;
	satb_flags_off = len;
	return 0;
}

int gcsatb_register(uint64_t start, uint64_t len)
{
	if (!satb_skel)
		return -1;
	if (!satb_link) {
		satb_link = bpf_map__attach_fault_ops(satb_skel->maps.gc_satb_ops,
						      (void *)start, len,
						      BPF_FAULT_FLAG_WP);
		if (!satb_link) {
			perror("gcsatb: attach");
			return -1;
		}
		return 0;
	}
	if (bpf_link__fault_register(bpf_link__fd(satb_link), start, len)) {
		perror("gcsatb: register");
		return -1;
	}
	return 0;
}

int gcsatb_wp(uint64_t start, uint64_t len, int enable)
{
	if (!satb_link)
		return -1;
	if (bpf_link_fault_cmd(bpf_link__fd(satb_link), start, len,
			       enable ? BPF_FAULT_WP_ENABLE : 0)) {
		perror("gcsatb: wp");
		return -1;
	}
	return 0;
}

uint8_t *gcsatb_flags(void)     { return satb_arena ? satb_arena + satb_flags_off : NULL; }
uint8_t *gcsatb_snapshots(void) { return satb_arena; }
void gcsatb_set_noop(unsigned int on)
{
	if (satb_skel)
		satb_skel->bss->satb_noop = on;
}

uint64_t gcsatb_snap_count(void)
{
	return satb_skel ? satb_skel->bss->satb_snapshots : 0;
}

/* ------------------------------------------------------------------ */
/*  Class B: fault-driven Compressor compaction (gc_b0_ops)            */
/* ------------------------------------------------------------------ */

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

#include "gc_b0_ops.skel.h"

static struct gc_b0_ops_bpf *b0_skel;
static struct bpf_link *b0_link;
static uint64_t *b0_state;
static uint64_t b0_space_base;
static uint64_t b0_arena_base;
static uint64_t b0_span;
static uint64_t b0_fwdtable; /* userspace base of the forward-table arena */
static uint64_t b0_refbits;  /* userspace base of the reference bitmap (in arena) */
static uint64_t b0_livebits; /* userspace base of the live-word bitmap (R1) */
static uint64_t b0_ov2;      /* userspace base of the per-512B-block new-address table */
static uint64_t b0_first_src;/* userspace base of the per-page first-src index (R1) */

/* Returns the arena base address, or 0 on failure. */
uint64_t gcb0_init(uint64_t space_base, uint64_t span_len)
{
	size_t pages = span_len / 4096;
	size_t map_bytes;
	long page = sysconf(_SC_PAGESIZE);
	void *arena;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Over-reserve and align the arena to the heap's 2 MiB phase so
	 * mremap can move whole PMD tables (move_normal_pmd) instead of
	 * individual PTEs — this is the difference between a ~60 ms and a
	 * sub-ms flip for a ~500 MB live heap. */
	{
		size_t pmd = 2UL << 20;
		void *raw = mmap(NULL, span_len + pmd, PROT_NONE,
				 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
				 -1, 0);
		if (raw == MAP_FAILED) {
			perror("gcb0: arena mmap");
			return 0;
		}
		uint64_t aligned = (((uint64_t)raw + pmd - 1) & ~(pmd - 1)) |
				   (space_base & (pmd - 1));
		if (aligned < (uint64_t)raw)
			aligned += pmd;
		arena = (void *)aligned;
	}

	b0_skel = gc_b0_ops_bpf__open();
	if (!b0_skel) {
		fprintf(stderr, "gcb0: open skeleton failed\n");
		return 0;
	}
	b0_skel->rodata->space_base = space_base;
	b0_skel->rodata->arena_base = (unsigned long)arena;
	b0_skel->rodata->span_len = span_len;
	if (bpf_map__set_max_entries(b0_skel->maps.page_state, pages)) {
		fprintf(stderr, "gcb0: set_max_entries failed\n");
		return 0;
	}
	/* BPF arena layout, each region page-aligned, all read directly by the
	 * prog: [ forward table (span/2) | reference bitmap (span/32) |
	 * live-word bitmap (span/64, R1) | first_src index (span/128, R1) ]. */
#define RUP(x) (((x) + page - 1) & ~(size_t)(page - 1))
	size_t refbm_off    = RUP(span_len / 2);
	size_t livebm_off   = refbm_off  + RUP(span_len / 32);
	size_t firstsrc_off = livebm_off + RUP(span_len / 64);
	size_t ov2_off      = firstsrc_off + RUP(span_len / 128);
	size_t arena_bytes  = ov2_off + RUP(span_len / 64);
#undef RUP
	{
		if (bpf_map__set_max_entries(b0_skel->maps.fwd_arena, arena_bytes / page)) {
			fprintf(stderr, "gcb0: arena set_max_entries failed\n");
			return 0;
		}
	}
	if (gc_b0_ops_bpf__load(b0_skel)) {
		fprintf(stderr, "gcb0: load failed (root? memlock?)\n");
		return 0;
	}
	b0_skel->bss->refbm_off = refbm_off;
	b0_skel->bss->livebm_off = livebm_off;
	b0_skel->bss->firstsrc_off = firstsrc_off;
	b0_skel->bss->ov2_off = ov2_off;
	/* mmap the arena so the GC can write the forward table + reference
	 * bitmap; the BPF prog reads them directly via arena pointers (no
	 * probe_read).  Arenas must map at their user_vm_start (= map_extra)
	 * with MAP_FIXED. */
	{
		uint64_t va = 1ull << 44; /* must match map_extra in the bpf prog */
		void *a = mmap((void *)va, arena_bytes, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_FIXED, bpf_map__fd(b0_skel->maps.fwd_arena), 0);
		if (a == MAP_FAILED) {
			perror("gcb0: mmap fwd_arena");
			return 0;
		}
		b0_fwdtable = (uint64_t)a;
		b0_refbits = (uint64_t)a + refbm_off;
		b0_livebits = (uint64_t)a + livebm_off;
		b0_first_src = (uint64_t)a + firstsrc_off;
		b0_ov2 = (uint64_t)a + ov2_off;
	}

	map_bytes = (pages * sizeof(uint64_t) + page - 1) & ~(page - 1);
	b0_state = mmap(NULL, map_bytes, PROT_READ | PROT_WRITE, MAP_SHARED,
			bpf_map__fd(b0_skel->maps.page_state), 0);
	if (b0_state == MAP_FAILED) {
		perror("gcb0: mmap page_state");
		b0_state = NULL;
		return 0;
	}

	b0_space_base = space_base;
	b0_arena_base = (uint64_t)arena;
	b0_span = span_len;
	return b0_arena_base;
}

/* Class B v2: set the JVM-dependent forward params (compressed-oops base/shift
 * and the defer flag).  The arena layout (table at offset 0, refbits at
 * refbm_off) is set in gcb0_init. */
void gcb0_set_forward(uint64_t coops_base, unsigned int coops_shift,
		      unsigned int defer, unsigned int inkernel)
{
	if (!b0_skel)
		return;
	b0_skel->bss->coops_base = coops_base;
	b0_skel->bss->coops_shift = coops_shift;
	b0_skel->bss->defer_fwd = defer;
	b0_skel->bss->inkernel = inkernel;
}

uint64_t gcb0_refs_forwarded(void)
{
	return b0_skel ? b0_skel->bss->b0_refs_forwarded : 0;
}

uint64_t gcb0_compact_words(void) { return b0_skel ? b0_skel->bss->b0_compact_words : 0; }
uint64_t gcb0_prefail(void) { return b0_skel ? b0_skel->bss->b0_prefail : 0; }
void gcb0_dbg_print(void) {
	if (!b0_skel) return;
	fprintf(stderr, "[r1dbg] off=0x%llx srcw0=%llu scratch0=0x%llx live0=0x%llx set=%llu\n",
		(unsigned long long)b0_skel->bss->dbg_off,
		(unsigned long long)b0_skel->bss->dbg_srcw0,
		(unsigned long long)b0_skel->bss->dbg_scratch0,
		(unsigned long long)b0_skel->bss->dbg_live0,
		(unsigned long long)b0_skel->bss->dbg_set);
	fprintf(stderr, "[r1cnt] staged_installs=%llu refs_fwd=%llu fault_count=%llu\n",
		(unsigned long long)b0_skel->bss->b0_staged_installs,
		(unsigned long long)b0_skel->bss->b0_refs_forwarded,
		(unsigned long long)b0_skel->bss->b0_fault_count);
	fprintf(stderr, "[r1page] off=0x%llx w=", (unsigned long long)b0_skel->bss->dbg_off);
	for (int j = 0; j < 8; j++)
		fprintf(stderr, "%llx ", (unsigned long long)b0_skel->bss->dbg_w[j]);
	fprintf(stderr, "\n");
}

/* Userspace bases of the arena regions: the GC writes the forward table and
 * reference bitmap here; the prog reads the same memory in-kernel. */
uint64_t gcb0_fwdtable_base(void)
{
	return b0_fwdtable;
}

uint64_t gcb0_refbits_base(void)
{
	return b0_refbits;
}

uint64_t gcb0_livebits_base(void)
{
	return b0_livebits;
}

uint64_t gcb0_first_src_base(void)
{
	return b0_first_src;
}

uint64_t gcb0_ov2_base(void)
{
	return b0_ov2;
}

/* Transducer forward: fwd(old) = ov2[block] + 8*popcount(live bits below
 * old in its 512B block) -- two cache-resident arena loads instead of one
 * load into the cache-hostile flat table.  check=1 additionally computes
 * the flat-table value and counts mismatches (validation). */
void gcb0_set_fwd_transducer(unsigned int on, unsigned int check)
{
	if (!b0_skel)
		return;
	b0_skel->bss->fwd_transducer = on;
	b0_skel->bss->fwd_check = check;
}

/* Enable in-handler ref/word counters (debug only: contended atomics). */
void gcb0_set_count_refs(unsigned int on)
{
	if (!b0_skel)
		return;
	b0_skel->bss->count_refs = on;
}

uint64_t gcb0_fwd_mismatch(void)
{
	return b0_skel ? b0_skel->bss->b0_fwd_mismatch : 0;
}

/* Flip a region: move its physical pages into the arena slot and (if
 * do_register) register the original range for missing-fault handling.
 * Registration persists across cycles (mremap MREMAP_DONTUNMAP keeps the
 * source VMA and its fault context), so callers skip it after the first
 * cycle. */
int gcb0_flip(uint64_t start, uint64_t len, int do_register)
{
	void *dst = (void *)(b0_arena_base + (start - b0_space_base));
	void *r;

	if (!b0_skel)
		return -1;
	r = mremap((void *)start, len, len,
		   MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, dst);
	if (r == MAP_FAILED) {
		perror("gcb0: mremap flip");
		return -1;
	}
	if (!do_register)
		return 0;
	if (!b0_link) {
		b0_link = bpf_map__attach_fault_ops(b0_skel->maps.gc_b0_ops,
						    (void *)start, len, 0);
		if (!b0_link) {
			perror("gcb0: attach_fault_ops");
			return -1;
		}
		return 0;
	}
	if (bpf_link__fault_register(bpf_link__fd(b0_link), start, len)) {
		/* Already registered from a previous cycle is fine. */
		if (errno != EBUSY && errno != EEXIST) {
			perror("gcb0: fault_register");
			return -1;
		}
	}
	return 0;
}

int gcb0_unregister(uint64_t start, uint64_t len)
{
	if (!b0_link)
		return 0;
	return bpf_link__fault_unregister(bpf_link__fd(b0_link), start, len);
}

/* Register a range with the b0 link (first call attaches). */
int gcb0_register(uint64_t start, uint64_t len)
{
	if (!b0_skel)
		return -1;
	if (!b0_link) {
		b0_link = bpf_map__attach_fault_ops(b0_skel->maps.gc_b0_ops,
						    (void *)start, len, 0);
		return b0_link ? 0 : -1;
	}
	if (bpf_link__fault_register(bpf_link__fd(b0_link), start, len)) {
		if (errno != EBUSY && errno != EEXIST) {
			perror("gcb0: fault_register");
			return -1;
		}
	}
	return 0;
}

/* Unmap a region's arena slot once all its pages are installed, keeping the
 * VMA count flat across GC cycles. */
int gcb0_unmap_arena(uint64_t start, uint64_t len)
{
	void *slot = (void *)(b0_arena_base + (start - b0_space_base));

	return munmap(slot, len);
}

uint64_t *gcb0_state(void)
{
	return b0_state;
}

uint64_t gcb0_fault_count(void)
{
	return b0_skel ? b0_skel->bss->b0_fault_count : 0;
}

uint64_t gcb0_staged_installs(void)
{
	return b0_skel ? b0_skel->bss->b0_staged_installs : 0;
}

/* ------------------------------------------------------------------ */
/*  Idea 6: compressed cold heap (gc_z_ops)                            */
/*  Arena layout: [offtab 4B/page][hot flags 1B/page][packed store]    */
/* ------------------------------------------------------------------ */

#include "gc_z_ops.skel.h"

static struct gc_z_ops_bpf *z_skel;
static struct bpf_link *z_link;
static uint8_t *z_arena;
static uint64_t z_base, z_span, z_flags_off, z_store_off, z_store_end;
static uint64_t z_cursor;          /* store allocation cursor */
static uint64_t z_compressed_bytes, z_original_bytes;

int gcz_init(uint64_t start, uint64_t len, uint64_t store_bytes)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t npages = len >> 12;
	size_t offtab_bytes = (npages * 4 + page - 1) & ~(size_t)(page - 1);
	size_t flags_bytes = (npages + page - 1) & ~(size_t)(page - 1);
	size_t arena_bytes = offtab_bytes + flags_bytes + store_bytes;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	z_skel = gc_z_ops_bpf__open();
	if (!z_skel)
		return -1;
	z_skel->rodata->heap_base = start;
	z_skel->rodata->span_len = len;
	arena_bytes = (arena_bytes + page - 1) & ~(size_t)(page - 1);
	if (bpf_map__set_max_entries(z_skel->maps.z_arena, arena_bytes / page))
		return -1;
	if (gc_z_ops_bpf__load(z_skel)) {
		fprintf(stderr, "gcz: load failed (root?)\n");
		return -1;
	}
	z_skel->bss->offtab_off = 0;
	z_skel->bss->zflags_off = offtab_bytes;
	z_arena = mmap((void *)(1ull << 46), arena_bytes,
		       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
		       bpf_map__fd(z_skel->maps.z_arena), 0);
	if (z_arena == MAP_FAILED) {
		perror("gcz: mmap arena");
		z_arena = NULL;
		return -1;
	}
	/* offtab = all 0xff (not compressed); rest zero; pre-touch all */
	memset(z_arena, 0xff, offtab_bytes);
	for (size_t i = offtab_bytes; i < arena_bytes; i += page)
		z_arena[i] = 0;
	z_base = start;
	z_span = len;
	z_flags_off = offtab_bytes;
	z_store_off = offtab_bytes + flags_bytes;
	z_store_end = arena_bytes;
	z_cursor = z_store_off;
	return 0;
}

int gcz_register(uint64_t start, uint64_t len)
{
	if (!z_skel)
		return -1;
	if (!z_link) {
		z_link = bpf_map__attach_fault_ops(z_skel->maps.gc_z_ops,
						   (void *)start, len, 0);
		if (!z_link) {
			perror("gcz: attach");
			return -1;
		}
		return 0;
	}
	if (bpf_link__fault_register(bpf_link__fd(z_link), start, len)) {
		perror("gcz: register");
		return -1;
	}
	return 0;
}

/* Compress one PRESENT heap page into the store and release it.
 * Returns compressed size, 0 if the store is full, -1 on error. */
long gcz_compress_page(uint64_t addr)
{
	const uint64_t *src = (const uint64_t *)addr;
	size_t idx = (addr - z_base) >> 12;
	uint32_t *offtab = (uint32_t *)z_arena;
	uint16_t *prefix;
	uint64_t *tags, *payload, cur;
	size_t n = 0;

	if (!z_arena || addr < z_base || addr >= z_base + z_span)
		return -1;
	cur = (z_cursor + 7) & ~7ull;
	if (cur + 16 + 64 + 4096 > z_store_end)
		return 0;              /* store full: skip */
	prefix = (uint16_t *)(z_arena + cur);
	tags = (uint64_t *)(z_arena + cur + 16);
	payload = (uint64_t *)(z_arena + cur + 16 + 64);
	for (int g = 0; g < 8; g++) {
		uint64_t tag = 0;
		prefix[g] = (uint16_t)n;
		for (int b = 0; b < 64; b++) {
			uint64_t w = src[g * 64 + b];
			if (w) {
				tag |= 1ull << b;
				payload[n++] = w;
			}
		}
		tags[g] = tag;
	}
	offtab[idx] = (uint32_t)cur;
	z_arena[z_flags_off + idx] = 0;
	__sync_synchronize();
	if (madvise((void *)addr, 4096, MADV_DONTNEED)) {
		offtab[idx] = 0xffffffff;   /* roll back */
		return -1;
	}
	z_cursor = cur + 16 + 64 + n * 8;
	z_compressed_bytes += 16 + 64 + n * 8;
	z_original_bytes += 4096;
	return (long)(16 + 64 + n * 8);
}

/* Page decompressed since last call? (kernel sets flag on decode) */
int gcz_take_hot(uint64_t addr)
{
	size_t idx = (addr - z_base) >> 12;
	if (!z_arena)
		return 0;
	if (z_arena[z_flags_off + idx]) {
		z_arena[z_flags_off + idx] = 0;
		((uint32_t *)z_arena)[idx] = 0xffffffff; /* entry stale */
		return 1;
	}
	return 0;
}

/* Invalidate a page's compressed image (page freed/decompressed). */
void gcz_invalidate(uint64_t addr)
{
	if (!z_arena || addr < z_base || addr >= z_base + z_span)
		return;
	((uint32_t *)z_arena)[(addr - z_base) >> 12] = 0xffffffff;
}

int gcz_is_compressed(uint64_t addr)
{
	if (!z_arena || addr < z_base || addr >= z_base + z_span)
		return 0;
	return ((uint32_t *)z_arena)[(addr - z_base) >> 12] != 0xffffffff;
}

void gcz_reset_store(void)
{
	if (z_arena)
		z_cursor = z_store_off;
}

uint64_t gcz_stats(uint64_t *orig, uint64_t *faults)
{
	if (orig)
		*orig = z_original_bytes;
	if (faults && z_skel)
		*faults = z_skel->bss->z_decoded;
	return z_compressed_bytes;
}

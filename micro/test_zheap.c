// SPDX-License-Identifier: GPL-2.0-only
/*
 * Compressed cold heap micro: compress pages in userspace
 * (zero-suppression), release the originals, register the missing-fault
 * decompressor (gc_z_ops), then touch every page and verify the decoded
 * contents match the originals.  Reports compression ratio and per-fault
 * decode latency.
 *
 * The scenario is a GC treating cold regions as compressible: footprint
 * drops to the compressed size + offset table; the first access pays one
 * in-kernel decode (~fault + tag-driven copy) instead of a userfaultfd
 * round-trip plus userspace decode.
 */
#include "gc_common.h"

#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_z_ops.skel.h"

#define WORDS (4096 / 8)

/* fill a page: ~zfrac of words zero, rest patterned */
static void fill_page(uint64_t *p, size_t i, double zfrac)
{
	unsigned int seed = (unsigned int)(i * 2654435761u);
	for (size_t w = 0; w < WORDS; w++) {
		seed = seed * 1103515245u + 12345u;
		if ((seed >> 16 & 0xffff) < (unsigned)(zfrac * 65536))
			p[w] = 0;
		else
			p[w] = ((uint64_t)i << 32) ^ (w * 0x9E3779B97F4A7C15ULL);
	}
}

/* encode a page; returns compressed byte size (16 prefix + 64 tags + payload) */
static size_t encode_page(const uint64_t *src, uint8_t *dst)
{
	uint16_t *prefix = (uint16_t *)dst;
	uint64_t *tags = (uint64_t *)(dst + 16);
	uint64_t *payload = (uint64_t *)(dst + 16 + 64);
	size_t n = 0;

	for (int g = 0; g < 8; g++) {
		prefix[g] = (uint16_t)n;
		uint64_t tag = 0;
		for (int b = 0; b < 64; b++) {
			uint64_t w = src[g * 64 + b];
			if (w != 0) {
				tag |= 1ULL << b;
				payload[n++] = w;
			}
		}
		tags[g] = tag;
	}
	return 16 + 64 + n * 8;
}

int main(int argc, char **argv)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t nr_pages = argc > 1 ? strtoul(argv[1], NULL, 0) : 65536;
	double zfrac = argc > 2 ? atof(argv[2]) : 0.6;
	size_t size = nr_pages * page;
	struct gc_z_ops_bpf *skel;
	struct bpf_link *link;
	int bad = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* originals (kept for verification) */
	uint64_t *orig = malloc(size);
	char *heap = alloc_anon_region(size, PROT_READ | PROT_WRITE);
	if (!heap || !orig)
		return 1;
	for (size_t i = 0; i < nr_pages; i++)
		fill_page(orig + i * WORDS, i, zfrac);
	memcpy(heap, orig, size);

	/* arena: [offset table (4B/page)][compressed images...] */
	size_t offtab_bytes = (nr_pages * 4 + page - 1) & ~(size_t)(page - 1);
	size_t arena_bytes = offtab_bytes + size + nr_pages * 128; /* worst case */
	arena_bytes = (arena_bytes + page - 1) & ~(size_t)(page - 1);

	skel = gc_z_ops_bpf__open();
	if (!skel)
		return 1;
	skel->rodata->heap_base = (unsigned long)heap;
	skel->rodata->span_len = size;
	if (bpf_map__set_max_entries(skel->maps.z_arena, arena_bytes / page)) {
		fprintf(stderr, "arena size failed\n");
		return 1;
	}
	if (gc_z_ops_bpf__load(skel)) {
		fprintf(stderr, "load failed (root?)\n");
		return 1;
	}
	skel->bss->offtab_off = 0;
	uint8_t *arena = mmap((void *)(1ull << 46), arena_bytes,
			      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
			      bpf_map__fd(skel->maps.z_arena), 0);
	if (arena == MAP_FAILED) {
		perror("mmap z_arena");
		return 1;
	}

	/* compress: userspace encode (this is the GC's cold-region pass) */
	uint32_t *offtab = (uint32_t *)arena;
	size_t cursor = offtab_bytes, total_comp = 0;
	uint64_t t0 = now_ns();
	for (size_t i = 0; i < nr_pages; i++) {
		offtab[i] = (uint32_t)cursor;
		size_t sz = encode_page((uint64_t *)(heap + i * page),
					arena + cursor);
		cursor += (sz + 7) & ~(size_t)7;
		total_comp += sz;
	}
	uint64_t t1 = now_ns();

	/* release the originals: the heap range becomes missing */
	if (madvise(heap, size, MADV_DONTNEED)) {
		perror("madvise");
		return 1;
	}
	link = bpf_map__attach_fault_ops(skel->maps.gc_z_ops, heap, size, 0);
	if (!link) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		return 1;
	}

	/* touch + verify: every page decodes in-kernel on first access */
	uint64_t *lat = calloc(nr_pages, sizeof(uint64_t));
	uint64_t t2 = now_ns();
	for (size_t i = 0; i < nr_pages; i++) {
		volatile uint64_t *p = (volatile uint64_t *)(heap + i * page);
		uint64_t b4 = now_ns();
		uint64_t v = *p;
		lat[i] = now_ns() - b4;
		(void)v;
		if (memcmp((void *)(heap + i * page), orig + i * WORDS, page)) {
			if (bad < 5)
				fprintf(stderr, "page %zu decode mismatch\n", i);
			bad++;
		}
	}
	uint64_t t3 = now_ns();

	struct lat_stats s = lat_compute(lat, nr_pages);
	printf("zheap: pages=%zu zfrac=%.2f compress=%.3fms decode_all=%.3fms\n",
	       nr_pages, zfrac, (t1 - t0) / 1e6, (t3 - t2) / 1e6);
	printf("ratio: %.2fx (%zu -> %zu bytes)\n",
	       (double)size / total_comp, size, total_comp);
	lat_print(&s);
	printf("faults=%llu decoded=%llu\n",
	       (unsigned long long)skel->bss->z_faults,
	       (unsigned long long)skel->bss->z_decoded);
	printf("RESULT test=zheap pages=%zu %s\n", nr_pages,
	       bad ? "FAIL" : "PASS");
	bpf_link__destroy(link);
	gc_z_ops_bpf__destroy(skel);
	return bad != 0;
}

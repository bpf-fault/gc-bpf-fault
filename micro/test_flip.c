// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test the ART-CMC "flip" primitive on bpf_fault (Class B foundation):
 *
 *   1. Populate a region (the heap before compaction).
 *   2. mremap(MREMAP_MAYMOVE|MREMAP_FIXED|MREMAP_DONTUNMAP) its physical
 *      pages to a from-space alias; the original range becomes an empty
 *      anonymous mapping.
 *   3. Attach a bpf_fault missing-fault handler to the original range that
 *      copies each page back from the alias in-kernel (gc_compact_ops).
 *   4. Touch every page of the original range; verify contents survive the
 *      round trip; report per-fault latency.
 *
 * This is exactly the kernel path a concurrent Compressor needs per region.
 */
#include "gc_common.h"

#include <errno.h>
#include <pthread.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_compact_ops.skel.h"

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

int main(int argc, char **argv)
{
	long page_size = sysconf(_SC_PAGESIZE);
	size_t nr_pages = argc > 1 ? strtoul(argv[1], NULL, 0) : 4096;
	size_t size = nr_pages * page_size;
	struct gc_compact_ops_bpf *skel;
	struct bpf_link *link;
	uint64_t *lat = calloc(nr_pages, sizeof(uint64_t));
	int bad = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* 1. The "heap": populated with stamps. */
	char *heap = alloc_anon_region(size, PROT_READ | PROT_WRITE);
	if (!heap)
		return 1;
	for (size_t i = 0; i < nr_pages; i++) {
		char *p = heap + i * page_size;
		memset(p, 0xAB, page_size);
		*(uint64_t *)p = i ^ 0x5a5a5a5a;
	}

	/* 2. Flip: move physical pages to the alias. */
	char *alias = alloc_anon_region(size, PROT_READ | PROT_WRITE);
	if (!alias)
		return 1;
	uint64_t t0 = now_ns();
	void *r = mremap(heap, size, size,
			 MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP,
			 alias);
	uint64_t t1 = now_ns();
	if (r == MAP_FAILED) {
		perror("mremap(MREMAP_DONTUNMAP)");
		return 1;
	}

	/* 3. Register the now-empty heap range with bpf_fault. */
	skel = gc_compact_ops_bpf__open();
	if (!skel)
		return 1;
	skel->rodata->to_base = (unsigned long)heap;
	skel->rodata->from_base = (unsigned long)alias;
	skel->rodata->region_len = size;
	if (gc_compact_ops_bpf__load(skel)) {
		fprintf(stderr, "load failed (root?)\n");
		return 1;
	}
	uint64_t t2 = now_ns();
	link = bpf_map__attach_fault_ops(skel->maps.gc_compact_ops,
					 heap, size, 0);
	uint64_t t3 = now_ns();
	if (!link) {
		fprintf(stderr, "attach_fault_ops after mremap failed: %s\n",
			strerror(errno));
		return 1;
	}

	/* 4. Materialize by touching; verify. */
	for (size_t i = 0; i < nr_pages; i++) {
		volatile uint64_t *p =
			(volatile uint64_t *)(heap + i * page_size);
		uint64_t before = now_ns();
		uint64_t v = *p;
		lat[i] = now_ns() - before;
		if (v != (i ^ 0x5a5a5a5a) ||
		    *((volatile unsigned char *)p + page_size - 1) != 0xAB) {
			if (bad < 5)
				fprintf(stderr, "page %zu corrupt\n", i);
			bad++;
		}
	}

	struct lat_stats s = lat_compute(lat, nr_pages);

	printf("flip: mremap(%zu pages)=%.3fms register=%.3fms\n",
	       nr_pages, (t1 - t0) / 1e6, (t3 - t2) / 1e6);
	lat_print(&s);
	printf("faults handled in-kernel: %llu\n",
	       (unsigned long long)skel->bss->missing_fault_count);
	printf(bad ? "FAIL: %d corrupt pages\n" : "PASS\n", bad);

	bpf_link__destroy(link);
	gc_compact_ops_bpf__destroy(skel);
	return bad != 0;
}

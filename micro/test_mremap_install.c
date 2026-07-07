// SPDX-License-Identifier: GPL-2.0-only
/*
 * mremap-install: can the concurrent Compressor's install phase move the
 * staged arena pages back into the heap with ONE mremap per region instead
 * of one missing-fault per page (the touch loop B.1 uses because bpf_fault
 * has no UFFDIO_COPY equivalent)?
 *
 * Per cycle:
 *   1. flip:    mremap(DONTUNMAP) heap -> arena alias; re-arm heap range
 *               with the missing-fault handler (fresh link each cycle,
 *               mirroring the JVM's per-flip registration).
 *   2. stage:   rewrite the alias contents (generation stamp) = compaction.
 *   3. install: mode "touch"      = touch every page (fault storm baseline);
 *               mode "move"       = mremap(MAYMOVE|FIXED) alias -> heap
 *                                   while the range is still armed;
 *               mode "move_unreg" = destroy the link first, then mremap.
 *   4. verify stamps; count VMAs covering the heap range (fragmentation
 *      across cycles is the open question for the real design).
 *
 * PASS requires every cycle to verify; the interesting outputs are
 * install-phase time and the VMA count trend.
 */
#include "gc_common.h"

#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_compact_ops.skel.h"

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

static int vma_count(void *start, size_t len)
{
	unsigned long lo = (unsigned long)start, hi = lo + len;
	char line[256];
	FILE *f = fopen("/proc/self/maps", "r");
	int n = 0;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		unsigned long s, e;
		if (sscanf(line, "%lx-%lx", &s, &e) == 2 && s < hi && e > lo)
			n++;
	}
	fclose(f);
	return n;
}

int main(int argc, char **argv)
{
	long page_size = sysconf(_SC_PAGESIZE);
	const char *mode = argc > 1 ? argv[1] : "move";
	size_t nr_pages = argc > 2 ? strtoul(argv[2], NULL, 0) : 16384;
	int cycles = argc > 3 ? atoi(argv[3]) : 5;
	size_t size = nr_pages * page_size;
	struct gc_compact_ops_bpf *skel;
	struct bpf_link *link = NULL;
	int bad = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	char *heap = alloc_anon_region(size, PROT_READ | PROT_WRITE);
	char *alias = alloc_anon_region(size, PROT_READ | PROT_WRITE);
	if (!heap || !alias)
		return 1;

	/* Populate generation 0 in the heap. */
	for (size_t i = 0; i < nr_pages; i++) {
		char *p = heap + i * page_size;
		memset(p, 0xAB, page_size);
		*(uint64_t *)p = i ^ 0x5a5a5a5aULL;
	}

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

	for (int g = 1; g <= cycles; g++) {
		/* 1. flip */
		uint64_t t0 = now_ns();
		void *r = mremap(heap, size, size,
				 MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP,
				 alias);
		uint64_t t1 = now_ns();
		if (r == MAP_FAILED) {
			printf("cycle %d: flip mremap FAILED: %s (vmas=%d)\n",
			       g, strerror(errno), vma_count(heap, size));
			return 1;
		}
		if (link)
			bpf_link__destroy(link);
		link = bpf_map__attach_fault_ops(skel->maps.gc_compact_ops,
						 heap, size, 0);
		uint64_t t2 = now_ns();
		if (!link) {
			printf("cycle %d: re-attach FAILED: %s (vmas=%d)\n",
			       g, strerror(errno), vma_count(heap, size));
			return 1;
		}

		/* 2. stage generation g into the alias */
		uint64_t t3 = now_ns();
		for (size_t i = 0; i < nr_pages; i++)
			*(uint64_t *)(alias + i * page_size) =
				i ^ 0x5a5a5a5aULL ^ ((uint64_t)g << 32);
		uint64_t t4 = now_ns();

		/* 3. install */
		uint64_t t5 = now_ns(), t6;
		if (!strcmp(mode, "touch")) {
			for (size_t i = 0; i < nr_pages; i++) {
				volatile uint64_t *p =
					(volatile uint64_t *)(heap + i * page_size);
				(void)*p;
			}
			t6 = now_ns();
		} else {
			if (!strcmp(mode, "move_unreg")) {
				bpf_link__destroy(link);
				link = NULL;
			}
			r = mremap(alias, size, size,
				   MREMAP_MAYMOVE | MREMAP_FIXED, heap);
			t6 = now_ns();
			if (r == MAP_FAILED) {
				printf("cycle %d: install mremap FAILED: %s (vmas=%d)\n",
				       g, strerror(errno), vma_count(heap, size));
				return 1;
			}
			/* the alias slot was moved out; re-create it for the
			 * next cycle's flip destination */
			if (mmap(alias, size, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
				 -1, 0) == MAP_FAILED) {
				perror("alias re-mmap");
				return 1;
			}
		}

		/* 4. verify */
		int cbad = 0;
		for (size_t i = 0; i < nr_pages; i++) {
			uint64_t want = i ^ 0x5a5a5a5aULL ^ ((uint64_t)g << 32);
			volatile uint64_t *p =
				(volatile uint64_t *)(heap + i * page_size);
			if (*p != want)
				cbad++;
		}
		bad += cbad;
		printf("cycle %d mode=%s: flip=%.3fms rearm=%.3fms stage=%.3fms "
		       "install=%.3fms verify=%s(%d bad) vmas=%d faults=%llu\n",
		       g, mode, (t1 - t0) / 1e6, (t2 - t1) / 1e6,
		       (t4 - t3) / 1e6, (t6 - t5) / 1e6,
		       cbad ? "FAIL" : "ok", cbad, vma_count(heap, size),
		       (unsigned long long)skel->bss->missing_fault_count);
	}

	printf("RESULT test=mremap_install mode=%s pages=%zu cycles=%d %s\n",
	       mode, nr_pages, cycles, bad ? "FAIL" : "PASS");
	if (link)
		bpf_link__destroy(link);
	gc_compact_ops_bpf__destroy(skel);
	return bad != 0;
}

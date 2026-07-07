// SPDX-License-Identifier: GPL-2.0-only
/*
 * WP_ENABLE coverage: arm N present pages, write each once, count
 * handler invocations.  Expect exactly N.  (A JVM trace showed only 753
 * WP faults where tens of thousands were expected — either most pages
 * were not protected, or most writes bypass the handler.)
 *
 * Variants probed: freshly-written pages, DONTNEED-then-retouched pages,
 * fork-shared? (no), and pages made non-exclusive via... keep simple:
 * fresh + retouched.
 */
#include "gc_common.h"

#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_wp_ops.skel.h"

int main(int argc, char **argv)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t npages = argc > 1 ? strtoul(argv[1], NULL, 0) : 4096;
	size_t size = npages * page;
	struct gc_wp_ops_bpf *skel;
	struct bpf_link *link;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	char *heap = alloc_anon_region(size, PROT_READ | PROT_WRITE);
	if (!heap)
		return 1;
	memset(heap, 0x11, size);          /* all present + dirty */

	skel = gc_wp_ops_bpf__open();
	skel->rodata->heap_base = (unsigned long)heap;
	if (bpf_map__set_max_entries(skel->maps.dirty_bitmap, 1))
		return 1;
	if (gc_wp_ops_bpf__load(skel)) {
		fprintf(stderr, "load failed (root?)\n");
		return 1;
	}
	skel->bss->wp_count_faults = 1;
	link = bpf_map__attach_fault_ops(skel->maps.gc_wp_ops, heap, size,
					 BPF_FAULT_FLAG_WP);
	if (!link) {
		perror("attach");
		return 1;
	}

	for (int round = 0; round < 3; round++) {
		uint64_t before = skel->bss->wp_fault_count;
		if (bpf_link_fault_cmd(bpf_link__fd(link), (uint64_t)heap,
				       size, BPF_FAULT_WP_ENABLE)) {
			perror("WP enable");
			return 1;
		}
		for (size_t i = 0; i < npages; i++)
			heap[i * page] = (char)round;
		uint64_t got = skel->bss->wp_fault_count - before;
		printf("round %d: faults=%llu expect=%zu %s\n", round,
		       (unsigned long long)got, npages,
		       got == npages ? "OK" : "MISMATCH");
		if (round == 1) {
			/* round 2 rewrites half the pages via DONTNEED */
			if (madvise(heap, size / 2, MADV_DONTNEED))
				return 1;
			memset(heap, 0x22, size / 2);
		}
	}
	bpf_link__destroy(link);
	gc_wp_ops_bpf__destroy(skel);
	return 0;
}

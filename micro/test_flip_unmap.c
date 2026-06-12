// SPDX-License-Identifier: GPL-2.0-only
/*
 * Reproducer for the Class B.1 crash: munmap of an mremap(MREMAP_DONTUNMAP)
 * destination VMA after the *source* range was registered with bpf_fault.
 *
 * Models exactly what compact_faults::finish_region did:
 *   1. heap region populated, then mremap(MREMAP_DONTUNMAP) to an arena slot
 *      (source 'heap' becomes empty, pages live at 'arena' slot).
 *   2. register the emptied 'heap' range with a bpf_fault missing handler
 *      that copies pages back from the arena slot.
 *   3. fault some pages back in (in-kernel copy from arena), then munmap the
 *      arena slot.
 *   4. fault the REMAINING heap pages — does in-kernel copy still work, or
 *      does the kernel mis-handle the now-unmapped arena source?
 *
 * Run multiple cycles (-c) to mimic repeated GCs.  Reports PASS/FAIL and
 * any corruption.
 */
#include "gc_common.h"

#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_compact_ops.skel.h"

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

static long ps;

int main(int argc, char **argv)
{
	ps = sysconf(_SC_PAGESIZE);
	size_t nr_pages = argc > 1 ? strtoul(argv[1], NULL, 0) : 256;
	int cycles = argc > 2 ? atoi(argv[2]) : 3;
	size_t size = nr_pages * ps;
	int do_unmap = argc > 3 ? atoi(argv[3]) : 1; /* 1=munmap 0=MADV_DONTNEED */
	int unreg = argc > 4 ? atoi(argv[4]) : 0;    /* 1=unregister before release */
	struct gc_compact_ops_bpf *skel;
	struct bpf_link *link = NULL;
	int bad = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Fixed heap + arena (arena holds the moved-away pages). */
	char *heap = mmap((void *)0x40000000UL, size, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	char *arena = mmap(NULL, size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (heap == MAP_FAILED || arena == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	skel = gc_compact_ops_bpf__open();
	if (!skel)
		return 1;
	skel->rodata->to_base = (unsigned long)heap;
	skel->rodata->from_base = (unsigned long)arena;
	skel->rodata->region_len = size;
	if (gc_compact_ops_bpf__load(skel)) {
		fprintf(stderr, "load failed (root?)\n");
		return 1;
	}

	for (int c = 0; c < cycles; c++) {
		/* Re-stamp the heap and flip it into the arena. */
		for (size_t i = 0; i < nr_pages; i++)
			*(uint64_t *)(heap + i * ps) = (c << 24) | i;
		void *r = mremap(heap, size, size,
				 MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP,
				 arena);
		if (r == MAP_FAILED) {
			perror("mremap flip");
			return 1;
		}

		/* Register (first cycle attaches; later cycles re-register). */
		if (!link) {
			link = bpf_map__attach_fault_ops(
				skel->maps.gc_compact_ops, heap, size, 0);
			if (!link) {
				fprintf(stderr, "attach failed: %s\n",
					strerror(errno));
				return 1;
			}
		} else if (bpf_link__fault_register(bpf_link__fd(link),
						    (unsigned long)heap, size)) {
			if (errno != EBUSY && errno != EEXIST) {
				perror("fault_register");
				return 1;
			}
		}

		/* Fault back the FIRST half via the in-kernel handler. */
		for (size_t i = 0; i < nr_pages / 2; i++) {
			uint64_t v = *(volatile uint64_t *)(heap + i * ps);
			if (v != (uint64_t)((c << 24) | i)) {
				if (bad < 5)
					fprintf(stderr,
						"cycle %d page %zu (pre-unmap) got %lx\n",
						c, i, v);
				bad++;
			}
		}

		/* Optionally unregister the region first, so a later fault is
		 * normal anonymous zero-fill instead of an arena read. */
		if (unreg)
			bpf_link__fault_unregister(bpf_link__fd(link),
						   (unsigned long)heap, size);

		/* Drop the arena slot — the operation under test. */
		if (do_unmap) {
			if (munmap(arena, size)) {
				perror("munmap arena");
				return 1;
			}
			/* Re-establish the arena mapping for the next cycle. */
			arena = mmap(arena, size, PROT_READ | PROT_WRITE,
				     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
				     -1, 0);
			if (arena == MAP_FAILED) {
				perror("re-mmap arena");
				return 1;
			}
		} else {
			madvise(arena, size, MADV_DONTNEED);
		}

		/* Fault the SECOND half: their arena source pages were just
		 * unmapped/discarded.  Correct behavior = zero-fill (handler
		 * reads unmapped user memory -> probe_read fails -> page is
		 * left zero) OR copy.  A kernel bug shows as a crash here, or
		 * the handler reading from a stale/wrong mapping. */
		for (size_t i = nr_pages / 2; i < nr_pages; i++) {
			volatile uint64_t v = *(volatile uint64_t *)(heap + i * ps);
			(void)v; /* value undefined post-discard; we test for crash */
		}

		/* Reset heap to a clean anonymous mapping for the next flip. */
		if (c + 1 < cycles) {
			munmap(heap, size);
			heap = mmap((void *)0x40000000UL, size,
				    PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
				    -1, 0);
			if (heap == MAP_FAILED) {
				perror("re-mmap heap");
				return 1;
			}
			skel->rodata->to_base = (unsigned long)heap;
			/* rodata is frozen post-load; this won't take effect.
			 * Keep heap at the same fixed address so to_base holds. */
		}
		printf("cycle %d done (faults=%llu)\n", c,
		       (unsigned long long)skel->bss->missing_fault_count);
	}

	printf("%s (bad=%d)\n", bad ? "FAIL" : "PASS", bad);
	if (link)
		bpf_link__destroy(link);
	gc_compact_ops_bpf__destroy(skel);
	return bad != 0;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Isolate the two factors that block PMD-granularity page-table moves in the
 * Class B flip mremap, to decide whether a kernel change is core-mm-wide or
 * bpf-fault-specific:
 *
 *   A. fresh destination (page tables not yet allocated)  -> move_normal_pmd
 *   B. MADV_DONTNEED'd destination (empty-but-present PTs) -> !pmd_none bail
 *
 * Both use a single, PMD-aligned, unregistered VMA, so VMA fragmentation is
 * NOT a factor here — this measures only the destination-PMD guard, which is
 * pure core mm (no uffd/bpf involved).  A big A-vs-B gap means the
 * move_normal_pmd `!pmd_none(*new_pmd)` guard is the blocker (a core change).
 */
#include "gc_common.h"

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

static long ps;

static void *aligned_anon(size_t size)
{
	size_t pmd = 2UL << 20;
	char *raw = mmap(NULL, size + pmd, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raw == MAP_FAILED)
		return NULL;
	uintptr_t a = ((uintptr_t)raw + pmd - 1) & ~(pmd - 1);
	return (void *)a;
}

int main(int argc, char **argv)
{
	ps = sysconf(_SC_PAGESIZE);
	size_t nr_pages = argc > 1 ? strtoul(argv[1], NULL, 0) : 262144; /* 1 GiB */
	size_t size = nr_pages * ps;

	char *src = aligned_anon(size);
	char *dst = aligned_anon(size);
	if (!src || !dst) {
		perror("mmap");
		return 1;
	}

	/* A. Fresh destination. */
	for (size_t i = 0; i < nr_pages; i++)
		src[i * ps] = 1;
	uint64_t t0 = now_ns();
	if (mremap(src, size, size,
		   MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, dst)
	    == MAP_FAILED) {
		perror("mremap A");
		return 1;
	}
	uint64_t a_ns = now_ns() - t0;

	/* Move it back so src is populated again, and leave dst with
	 * empty-but-present page tables via MADV_DONTNEED. */
	mremap(dst, size, size,
	       MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, src);
	madvise(dst, size, MADV_DONTNEED); /* frees pages, keeps PTE tables */

	/* B. DONTNEED'd destination (page tables present but empty). */
	t0 = now_ns();
	if (mremap(src, size, size,
		   MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, dst)
	    == MAP_FAILED) {
		perror("mremap B");
		return 1;
	}
	uint64_t b_ns = now_ns() - t0;

	printf("PMDMOVE pages=%zu A_fresh_ms=%.3f B_dontneed_ms=%.3f ratio=%.1fx\n",
	       nr_pages, a_ns / 1e6, b_ns / 1e6, (double)b_ns / (double)a_ns);
	printf("  A = %.1f ns/page  B = %.1f ns/page\n",
	       (double)a_ns / nr_pages, (double)b_ns / nr_pages);
	return 0;
}

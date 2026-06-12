// SPDX-License-Identifier: GPL-2.0-only
/*
 * Confirm that bpf_fault registration in 1 MiB chunks (as the Class B flip
 * does, one call per Compressor region) fragments the VMA and thereby
 * defeats PMD-granularity page-table moves in the flip mremap.
 *
 * Compares, for the same PMD-aligned region:
 *   single  — register the whole range in ONE call, then flip
 *   chunked — register in 1 MiB chunks, then flip
 * and counts the VMAs in /proc/self/maps for the range in each case.
 *
 * If chunked is much slower and shows many VMAs, the needed kernel change
 * is bpf-fault-specific (don't split / re-merge on registration), NOT a
 * core mm change.
 */
#include "gc_common.h"

#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "gc_compact_ops.skel.h"

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif
#define REGION (1UL << 20)

static long ps;

static int count_vmas(unsigned long lo, unsigned long hi)
{
	FILE *f = fopen("/proc/self/maps", "r");
	char line[256];
	int n = 0;

	while (fgets(line, sizeof(line), f)) {
		unsigned long s, e;
		if (sscanf(line, "%lx-%lx", &s, &e) == 2 &&
		    s >= lo && s < hi)
			n++;
	}
	fclose(f);
	return n;
}

static void *aligned_anon(size_t size)
{
	size_t pmd = 2UL << 20;
	char *raw = mmap(NULL, size + pmd, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raw == MAP_FAILED)
		return NULL;
	return (void *)(((uintptr_t)raw + pmd - 1) & ~(pmd - 1));
}

static double flip(struct gc_compact_ops_bpf *skel, struct bpf_link **link,
		   char *src, char *dst, size_t size, int chunked)
{
	size_t n = size / REGION;

	for (size_t i = 0; i < size / ps; i++)
		src[i * ps] = 1;

	/* Register (attach on first call). */
	if (!*link) {
		*link = bpf_map__attach_fault_ops(skel->maps.gc_compact_ops,
						  src, chunked ? REGION : size, 0);
		if (!*link) {
			fprintf(stderr, "attach: %s\n", strerror(errno));
			exit(1);
		}
		if (chunked)
			for (size_t i = 1; i < n; i++)
				bpf_link__fault_register(bpf_link__fd(*link),
					(unsigned long)src + i * REGION, REGION);
	}

	int vmas = count_vmas((unsigned long)src, (unsigned long)src + size);

	uint64_t t0 = now_ns();
	if (mremap(src, size, size,
		   MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, dst)
	    == MAP_FAILED) {
		perror("mremap");
		exit(1);
	}
	double ms = (now_ns() - t0) / 1e6;
	printf("  %-8s vmas=%-4d flip=%.3f ms (%.1f ns/page)\n",
	       chunked ? "chunked" : "single", vmas, ms,
	       ms * 1e6 / (size / ps));

	/* Restore + tidy for the next measurement. */
	mremap(dst, size, size,
	       MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, src);
	madvise(dst, size, MADV_DONTNEED);
	bpf_link__destroy(*link);
	*link = NULL;
	return ms;
}

int main(int argc, char **argv)
{
	ps = sysconf(_SC_PAGESIZE);
	size_t mb = argc > 1 ? strtoul(argv[1], NULL, 0) : 256;
	size_t size = mb << 20;
	struct gc_compact_ops_bpf *skel;
	struct bpf_link *link = NULL;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	char *src = aligned_anon(size);
	char *dst = aligned_anon(size);

	skel = gc_compact_ops_bpf__open();
	skel->rodata->to_base = (unsigned long)src;
	skel->rodata->from_base = (unsigned long)dst;
	skel->rodata->region_len = size;
	if (gc_compact_ops_bpf__load(skel)) {
		fprintf(stderr, "load failed (root?)\n");
		return 1;
	}

	printf("region = %zu MiB, %zu x 1MiB sub-regions:\n", mb, size / REGION);
	flip(skel, &link, src, dst, size, 0);
	flip(skel, &link, src, dst, size, 1);

	gc_compact_ops_bpf__destroy(skel);
	return 0;
}

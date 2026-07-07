// SPDX-License-Identifier: GPL-2.0-only
/*
 * WP fault transparency under concurrent same-page writes.
 *
 * Hypothesis (from the SATB bisect: a NO-OP WP handler corrupts a correct
 * Java run): when multiple threads write-fault the SAME armed page
 * simultaneously, the kernel's WP resolution loses stores (e.g., a racing
 * thread's write lands on a page that resolution replaces, or a stale-WP
 * TLB entry writes without fault after the PTE changed).
 *
 * Test: arm P pages with WP (no-op-ish dirty handler); N threads each
 * perform M atomic fetch-adds on their own slot of a SHARED page set,
 * with re-arming rounds in between to force repeated contended faults.
 * Verify every slot equals its expected count.  Any deficit = lost
 * stores = kernel bug demonstrated in ~100 lines.
 */
#include "gc_common.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_wp_ops.skel.h"

#define NPAGES 1024   /* 4MB: two 2MB THPs */

struct targs {
	_Atomic uint64_t *slots;   /* one slot per thread per page */
	int tid, nthreads, rounds, incs;
	pthread_barrier_t *bar;
	long page;
};

static void *worker(void *argp)
{
	struct targs *a = argp;
	for (int r = 0; r < a->rounds; r++) {
		pthread_barrier_wait(a->bar);   /* all threads hit armed pages together */
		for (int i = 0; i < a->incs; i++) {
			for (int p = 0; p < NPAGES; p++) {
				/* PLAIN stores (CHM-style): slot must end at
				 * the last value written this round */
				volatile uint64_t *slot =
					&((volatile uint64_t *)((char *)a->slots + p * a->page))[a->tid];
				*slot = ((uint64_t)r << 32) | (uint64_t)(i + 1);
			}
		}
		pthread_barrier_wait(a->bar);   /* round done; main re-arms */
	}
	return NULL;
}

int main(int argc, char **argv)
{
	long page = sysconf(_SC_PAGESIZE);
	int nthreads = argc > 1 ? atoi(argv[1]) : 8;
	int rounds = argc > 2 ? atoi(argv[2]) : 200;
	int incs = argc > 3 ? atoi(argv[3]) : 1000;
	size_t size = NPAGES * page;
	struct gc_wp_ops_bpf *skel;
	struct bpf_link *link;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Collapse to THP BEFORE attaching, like a long-running JVM heap:
	 * 2MB-aligned region, MADV_HUGEPAGE, fully touched. */
	size = (size + (4 << 20) - 1) & ~(size_t)((4 << 20) - 1);
	char *heap = mmap(NULL, size + (2 << 20), PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (heap == MAP_FAILED)
		return 1;
	heap = (char *)(((unsigned long)heap + (2 << 20) - 1) & ~(unsigned long)((2 << 20) - 1));
	if (madvise(heap, size, MADV_HUGEPAGE))
		perror("madvise HUGEPAGE");
	memset(heap, 0, size);
#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif
	if (madvise(heap, size, MADV_COLLAPSE))
		perror("MADV_COLLAPSE");
	{
		/* verify THP collapsed */
		char smaps[64];
		FILE *f = fopen("/proc/self/smaps_rollup", "r");
		char line[256];
		long ahp = 0;
		while (f && fgets(line, sizeof(line), f))
			if (sscanf(line, "AnonHugePages: %ld", &ahp) == 1)
				break;
		if (f) fclose(f);
		printf("AnonHugePages=%ldkB %s\n", ahp,
		       ahp >= 2048 ? "(THP present)" : "(NO THP!)");
		(void)smaps;
	}

	skel = gc_wp_ops_bpf__open();
	skel->rodata->heap_base = (unsigned long)heap;
	if (bpf_map__set_max_entries(skel->maps.dirty_bitmap, 1))
		return 1;
	if (gc_wp_ops_bpf__load(skel)) {
		fprintf(stderr, "load failed (root?)\n");
		return 1;
	}
	link = bpf_map__attach_fault_ops(skel->maps.gc_wp_ops, heap, size,
					 BPF_FAULT_FLAG_WP);
	if (!link) {
		perror("attach");
		return 1;
	}

	pthread_barrier_t bar;
	pthread_barrier_init(&bar, NULL, nthreads + 1);
	pthread_t th[64];
	struct targs args[64];
	for (int t = 0; t < nthreads; t++) {
		args[t] = (struct targs){ (_Atomic uint64_t *)heap, t, nthreads,
					  rounds, incs, &bar, page };
		pthread_create(&th[t], NULL, worker, &args[t]);
	}
	for (int r = 0; r < rounds; r++) {
		/* every 4th round: DONTNEED half the pages while armed, like
		 * immix sweeping freed blocks under registration (the JVM-only
		 * ingredient the plain race variant lacked) */
		if (r % 4 == 3) {
			if (madvise(heap, size / 2, MADV_DONTNEED)) {
				perror("madvise");
				return 1;
			}
		}
		/* re-arm all pages so every round starts write-protected */
		if (bpf_link_fault_cmd(bpf_link__fd(link), (uint64_t)heap, size,
				       BPF_FAULT_WP_ENABLE)) {
			perror("WP enable");
			return 1;
		}
		pthread_barrier_wait(&bar);   /* release writers */
		pthread_barrier_wait(&bar);   /* wait round end */
	}
	for (int t = 0; t < nthreads; t++)
		pthread_join(th[t], NULL);

	uint64_t expect = (((uint64_t)(rounds - 1)) << 32) | (uint64_t)incs;
	uint64_t lost = 0;
	for (int p = 0; p < NPAGES; p++) {
		for (int t = 0; t < nthreads; t++) {
			uint64_t v = ((uint64_t *)(heap + p * page))[t];
			if (v != expect) {
				printf("page %d slot %d: %llx != %llx (STALE STORE)\n",
				       p, t, (unsigned long long)v,
				       (unsigned long long)expect);
				lost += 1;
			}
		}
	}
	printf("RESULT test=wp_race threads=%d rounds=%d incs=%d lost=%llu %s\n",
	       nthreads, rounds, incs, (unsigned long long)lost,
	       lost ? "FAIL(KERNEL BUG)" : "PASS");
	bpf_link__destroy(link);
	gc_wp_ops_bpf__destroy(skel);
	return lost != 0;
}

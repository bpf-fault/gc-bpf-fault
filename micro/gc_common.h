/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared helpers for the gc-bpf-fault microbenchmarks: timing, latency
 * statistics, region allocation, and the bpf_fault link command wrappers.
 *
 * The BPF_LINK_FAULT_OPS_CMD constants mirror the bpf-fault kernel tree
 * (tools/testing/selftests/bpf/bench_fault/wp_util.h) until they land in
 * system headers.
 */
#ifndef GC_COMMON_H
#define GC_COMMON_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <linux/types.h>

#ifndef BPF_LINK_FAULT_OPS_CMD
#define BPF_LINK_FAULT_OPS_CMD	38
#endif
#ifndef BPF_FAULT_FLAG_WP
#define BPF_FAULT_FLAG_WP	(1U << 0)
#endif
#ifndef BPF_FAULT_FLAG_INHERIT
#define BPF_FAULT_FLAG_INHERIT	(1U << 1)
#endif
#ifndef BPF_FAULT_WP_ENABLE
#define BPF_FAULT_WP_ENABLE	(1U << 0)
#endif
#ifndef BPF_FAULT_REGISTER
#define BPF_FAULT_REGISTER	(1U << 1)
#endif
#ifndef BPF_FAULT_UNREGISTER
#define BPF_FAULT_UNREGISTER	(1U << 2)
#endif

struct bpf_link_fault_cmd_attr {
	__u32		link_fd;
	__u32		flags;
	__u64		start;
	__u64		len;
} __attribute__((aligned(8)));

static inline int bpf_link_fault_cmd(int link_fd, __u64 start, __u64 len,
				     __u32 flags)
{
	struct bpf_link_fault_cmd_attr attr = {
		.link_fd = link_fd,
		.flags = flags,
		.start = start,
		.len = len,
	};

	return syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD, &attr, sizeof(attr));
}

/* ------------------------------------------------------------------ */
/*  Timing                                                             */
/* ------------------------------------------------------------------ */

static inline uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/*  Latency statistics                                                 */
/* ------------------------------------------------------------------ */

struct lat_stats {
	uint64_t avg, min, max, p50, p99, p999;
	size_t n;
};

static inline int cmp_u64(const void *a, const void *b)
{
	uint64_t va = *(const uint64_t *)a;
	uint64_t vb = *(const uint64_t *)b;

	return (va > vb) - (va < vb);
}

/* Sorts in place. */
static inline struct lat_stats lat_compute(uint64_t *lat, size_t n)
{
	struct lat_stats s = { .n = n };
	uint64_t sum = 0;

	if (!n)
		return s;

	qsort(lat, n, sizeof(uint64_t), cmp_u64);
	for (size_t i = 0; i < n; i++)
		sum += lat[i];

	s.avg = sum / n;
	s.min = lat[0];
	s.max = lat[n - 1];
	s.p50 = lat[n / 2];
	s.p99 = lat[(size_t)(n * 0.99)];
	s.p999 = lat[(size_t)(n * 0.999)];
	return s;
}

static inline void lat_print(const struct lat_stats *s)
{
	printf("    Per-fault latency (ns): avg=%lu min=%lu p50=%lu p99=%lu p999=%lu max=%lu (n=%zu)\n",
	       s->avg, s->min, s->p50, s->p99, s->p999, s->max, s->n);
}

/* ------------------------------------------------------------------ */
/*  Regions and misc                                                   */
/* ------------------------------------------------------------------ */

static inline void *alloc_anon_region(size_t size, int prot)
{
	void *p = mmap(NULL, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}
	return p;
}

/* Fisher-Yates shuffle of a page-index permutation. */
static inline void shuffle_pages(size_t *perm, size_t n, unsigned int seed)
{
	for (size_t i = 0; i < n; i++)
		perm[i] = i;
	for (size_t i = n - 1; i > 0; i--) {
		size_t j = rand_r(&seed) % (i + 1);
		size_t t = perm[i];

		perm[i] = perm[j];
		perm[j] = t;
	}
}

static inline long context_switches(void)
{
	struct rusage ru;

	getrusage(RUSAGE_SELF, &ru);
	return ru.ru_nvcsw + ru.ru_nivcsw;
}

#endif /* GC_COMMON_H */

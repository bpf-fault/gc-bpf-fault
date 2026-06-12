// SPDX-License-Identifier: GPL-2.0-only
/*
 * Class B v2 microbenchmark: in-kernel compaction + reference fixup.
 *
 * Builds a from-space of fixed-size objects with inter-object references,
 * computes a sliding compaction (live objects renumbered), and registers an
 * empty to-space with a bpf_fault handler (gc_kfixup_ops) that materializes
 * each faulted to-space page IN-KERNEL: copying live objects from from-space
 * and rewriting their reference fields to the referents' new addresses.
 *
 * Verifies correctness (object data preserved; references point to the
 * correct post-compaction addresses) and compares cost against the B.0-style
 * userspace path (userspace compacts+fixes into an arena; in a real GC the
 * in-kernel handler would still need a final copy — here we contrast the
 * end-to-end materialization).
 */
#include "gc_common.h"

#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_kfixup_ops.skel.h"

#define OBJ_SIZE   64
#define OBJ_WORDS  (OBJ_SIZE / 8)
#define OBJS_PER_PAGE (4096 / OBJ_SIZE)
#define REF0 1
#define REF1 2

static long ps;

/* A from-space object, 8 words: [0]=header(old 1-based idx), [1]=ref0,
 * [2]=ref1 (1-based old indices, 0=null), [3..7]=data. */
static uint64_t expected_ref(uint64_t oldref, uint32_t *old2new, uint64_t to_base)
{
	if (oldref == 0)
		return 0;
	return to_base + (uint64_t)old2new[oldref] * OBJ_SIZE;
}

int main(int argc, char **argv)
{
	ps = sysconf(_SC_PAGESIZE);
	size_t total_objs = argc > 1 ? strtoul(argv[1], NULL, 0) : 1u << 20; /* 1M */
	double live_frac = argc > 2 ? atof(argv[2]) : 0.66;
	struct gc_kfixup_ops_bpf *skel;
	struct bpf_link *link;
	int bad = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	size_t from_bytes = total_objs * OBJ_SIZE;
	uint64_t *from = alloc_anon_region(from_bytes, PROT_READ | PROT_WRITE);
	if (!from)
		return 1;

	/* Decide liveness + build references. Object i (0-based) is live if
	 * (i % 3 != 2) up to live_frac; references point to live objects. */
	uint8_t *live = calloc(total_objs, 1);
	size_t nr_live = 0;
	for (size_t i = 0; i < total_objs; i++) {
		if ((double)nr_live < live_frac * (i + 1) && (i % 3 != 2)) {
			live[i] = 1;
			nr_live++;
		}
	}

	/* old (1-based) -> new (0-based); new -> old (1-based). */
	uint32_t *old2new = calloc(total_objs + 1, sizeof(uint32_t));
	uint32_t *new2old = calloc(nr_live, sizeof(uint32_t));
	uint32_t nidx = 0;
	for (size_t i = 0; i < total_objs; i++) {
		if (live[i]) {
			old2new[i + 1] = nidx;       /* 1-based old key */
			new2old[nidx] = (uint32_t)(i + 1);
			nidx++;
		}
	}

	/* Stamp from-space: header=old idx, refs to two live neighbours,
	 * data = pattern. */
	for (size_t i = 0; i < total_objs; i++) {
		uint64_t *o = from + i * OBJ_WORDS;
		o[0] = i + 1; /* header: 1-based old index */
		/* pick two live referents deterministically */
		uint64_t r0 = 0, r1 = 0;
		for (size_t k = 1; k <= 8; k++) {
			size_t j = (i + k) % total_objs;
			if (live[j]) { r0 = j + 1; break; }
		}
		for (size_t k = 1; k <= 8; k++) {
			size_t j = (i + total_objs - k) % total_objs;
			if (live[j]) { r1 = j + 1; break; }
		}
		o[REF0] = r0;
		o[REF1] = r1;
		for (int w = 3; w < OBJ_WORDS; w++)
			o[w] = (i + 1) * 1000 + w;
	}

	/* to-space: nr_live objects, page-rounded. */
	size_t to_bytes = ((nr_live * OBJ_SIZE + ps - 1) & ~(ps - 1));
	uint64_t *to = alloc_anon_region(to_bytes, PROT_READ | PROT_WRITE);
	if (!to)
		return 1;

	skel = gc_kfixup_ops_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }
	skel->rodata->to_base = (unsigned long)to;
	skel->rodata->from_base = (unsigned long)from;
	skel->rodata->span_len = to_bytes;
	skel->rodata->nr_objs = nr_live;
	bpf_map__set_max_entries(skel->maps.new2old, nr_live);
	bpf_map__set_max_entries(skel->maps.old2new, total_objs + 1);
	if (gc_kfixup_ops_bpf__load(skel)) {
		fprintf(stderr, "load failed (root?)\n");
		return 1;
	}
	/* populate the maps */
	for (uint32_t k = 0; k < nr_live; k++)
		bpf_map_update_elem(bpf_map__fd(skel->maps.new2old), &k, &new2old[k], 0);
	for (uint32_t k = 0; k <= total_objs; k++)
		if (old2new[k] || k == 0)
			bpf_map_update_elem(bpf_map__fd(skel->maps.old2new), &k, &old2new[k], 0);

	link = bpf_map__attach_fault_ops(skel->maps.gc_kfixup_ops, to, to_bytes, 0);
	if (!link) { fprintf(stderr, "attach: %s\n", strerror(errno)); return 1; }

	/* Materialize: touch every to-space page (in-kernel compaction+fixup). */
	size_t to_pages = to_bytes / ps;
	uint64_t *lat = calloc(to_pages, sizeof(uint64_t));
	uint64_t t0 = now_ns();
	for (size_t p = 0; p < to_pages; p++) {
		volatile uint64_t v = *(volatile uint64_t *)((char *)to + p * ps);
		(void)v;
		lat[p] = 0;
	}
	double mat_ms = (now_ns() - t0) / 1e6;

	/* Verify every live object. */
	for (uint32_t n = 0; n < nr_live && bad < 10; n++) {
		uint64_t *obj = to + (size_t)n * OBJ_WORDS;
		uint32_t old1 = new2old[n];
		uint64_t *src = from + (size_t)(old1 - 1) * OBJ_WORDS;
		if (obj[0] != old1) {
			fprintf(stderr, "obj %u: header %lu != %u\n", n, obj[0], old1); bad++;
		}
		uint64_t er0 = expected_ref(src[REF0], old2new, (uint64_t)to);
		uint64_t er1 = expected_ref(src[REF1], old2new, (uint64_t)to);
		if (obj[REF0] != er0) {
			fprintf(stderr, "obj %u: ref0 %lx != %lx (oldref %lu)\n",
				n, obj[REF0], er0, src[REF0]); bad++;
		}
		if (obj[REF1] != er1) {
			fprintf(stderr, "obj %u: ref1 %lx != %lx\n", n, obj[REF1], er1); bad++;
		}
		for (int w = 3; w < OBJ_WORDS; w++)
			if (obj[w] != src[w]) {
				fprintf(stderr, "obj %u w%d data mismatch\n", n, w); bad++; break;
			}
	}

	printf("kfixup: total_objs=%zu live=%zu (%.0f%%) to=%zuMB materialize=%.3fms\n",
	       total_objs, nr_live, 100.0 * nr_live / total_objs, to_bytes >> 20, mat_ms);
	printf("  in-kernel: faults=%llu objs=%llu refs=%llu  per-page=%.2fus\n",
	       (unsigned long long)skel->bss->kfixup_faults,
	       (unsigned long long)skel->bss->kfixup_objs,
	       (unsigned long long)skel->bss->kfixup_refs,
	       mat_ms * 1000.0 / to_pages);
	printf("%s\n", bad ? "FAIL" : "PASS");

	bpf_link__destroy(link);
	gc_kfixup_ops_bpf__destroy(skel);
	return bad ? 1 : 0;
}

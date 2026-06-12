// SPDX-License-Identifier: GPL-2.0-only
/*
 * Class B v2 microbench (BPF-arena edition): in-kernel compaction + fixup
 * with ARBITRARY reference layout identified by a GC-provided reference
 * bitmap.  from-space objects and all metadata live in a BPF arena; the
 * missing-fault handler reads them by direct pointer (no probe_read, no
 * per-element map lookup) and materializes each to-space page in-kernel.
 *
 * Each object has its references at object-specific word positions (not
 * fixed offsets) to exercise the reference bitmap — the mechanism that
 * lets the in-kernel handler forward pointers without knowing object
 * layout (the HotSpot-oop-map problem for real integration).
 */
#include "gc_common.h"
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "gc_kfixarena.skel.h"

#define OBJ_SIZE  64
#define OBJ_WORDS 8

/* Reference word positions for an object, as a function of its old index.
 * Returns count; fills pos[] with word indices in [1, OBJ_WORDS).  Word 0 is
 * the header (never a reference). */
static int ref_positions(uint64_t old1, int *pos)
{
	int n = 0;
	int a = 1 + (int)(old1 % 3);        /* 1..3 */
	int b = 4 + (int)((old1 / 3) % 4);  /* 4..7 */
	pos[n++] = a;
	if (b != a)
		pos[n++] = b;
	return n;
}

int main(int argc, char **argv)
{
	long ps = sysconf(_SC_PAGESIZE);
	size_t total = argc > 1 ? strtoul(argv[1], NULL, 0) : 1u << 20;
	double live_frac = argc > 2 ? atof(argv[2]) : 0.66;
	struct gc_kfixarena_bpf *skel;
	struct bpf_link *link;
	int bad = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	uint8_t *live = calloc(total, 1);
	size_t nr_live = 0;
	for (size_t i = 0; i < total; i++)
		if ((double)nr_live < live_frac * (i + 1) && (i % 3 != 2)) {
			live[i] = 1; nr_live++;
		}
	if (total > (1u << 20)) { fprintf(stderr, "total exceeds arena MAX_OBJS (1M); use <=1M\n"); return 1; }

	uint32_t *o2n = calloc(total + 1, sizeof(uint32_t));
	uint32_t *n2o = calloc(nr_live, sizeof(uint32_t));
	uint32_t nidx = 0;
	for (size_t i = 0; i < total; i++)
		if (live[i]) { o2n[i + 1] = nidx; n2o[nidx] = (uint32_t)(i + 1); nidx++; }

	size_t to_bytes = ((nr_live * OBJ_SIZE + ps - 1) & ~(ps - 1));
	uint64_t *to = alloc_anon_region(to_bytes, PROT_READ | PROT_WRITE);
	if (!to) return 1;

	skel = gc_kfixarena_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }
	skel->rodata->to_base = (unsigned long)to;
	skel->rodata->span_len = to_bytes;
	skel->rodata->nr_objs = nr_live;
	if (gc_kfixarena_bpf__load(skel)) { fprintf(stderr, "load failed (root? memlock?)\n"); return 1; }

	/* Populate the arena: from-space objects (by NEW order so they sit at
	 * old positions), forward tables, and the reference bitmap. */
	for (uint32_t n = 0; n < nr_live; n++) {
		uint64_t old1 = n2o[n];
		uint64_t *src = &skel->arena->from_space[(old1 - 1) * OBJ_WORDS];
		for (int w = 0; w < OBJ_WORDS; w++)
			src[w] = old1 * 1000 + w;          /* data */
		src[0] = old1;                             /* header */
		int pos[4]; int np = ref_positions(old1, pos);
		for (int k = 0; k < np; k++) {
			/* reference to a live object (old 1-based) */
			uint64_t target = n2o[(n + 1 + k) % nr_live];
			src[pos[k]] = target;
			/* mark the TO-space word as a reference */
			uint64_t tw = (uint64_t)n * OBJ_WORDS + pos[k];
			skel->arena->refbits[tw >> 6] |= (1ULL << (tw & 63));
		}
	}
	for (uint32_t n = 0; n < nr_live; n++)
		skel->arena->new2old[n] = n2o[n];
	for (size_t k = 0; k <= total; k++)
		skel->arena->old2new[k] = o2n[k];

	link = bpf_map__attach_fault_ops(skel->maps.gc_kfixarena, to, to_bytes, 0);
	if (!link) { fprintf(stderr, "attach: %s\n", strerror(errno)); return 1; }

	size_t to_pages = to_bytes / ps;
	uint64_t t0 = now_ns();
	for (size_t p = 0; p < to_pages; p++) {
		volatile uint64_t v = *(volatile uint64_t *)((char *)to + p * ps);
		(void)v;
	}
	double mat_ms = (now_ns() - t0) / 1e6;

	/* Verify: data preserved, references forwarded, layout arbitrary. */
	for (uint32_t n = 0; n < nr_live && bad < 10; n++) {
		uint64_t *obj = to + (size_t)n * OBJ_WORDS;
		uint64_t old1 = n2o[n];
		int pos[4]; int np = ref_positions(old1, pos);
		uint8_t isref[OBJ_WORDS] = {0};
		for (int k = 0; k < np; k++) isref[pos[k]] = 1;
		for (int w = 0; w < OBJ_WORDS; w++) {
			if (isref[w]) {
				uint64_t target = n2o[(n + 1 + (w==pos[0]?0:1)) % nr_live];
				uint64_t want = (uint64_t)to + (uint64_t)o2n[target] * OBJ_SIZE;
				if (obj[w] != want) {
					fprintf(stderr, "obj %u w%d ref %lx != %lx\n", n, w, obj[w], want);
					bad++;
				}
			} else {
				uint64_t want = (w == 0) ? old1 : old1 * 1000 + w;
				if (obj[w] != want) {
					fprintf(stderr, "obj %u w%d data %lx != %lx\n", n, w, obj[w], want);
					bad++;
				}
			}
		}
	}

	printf("kfixarena: total=%zu live=%zu to=%zuMB materialize=%.3fms per-page=%.2fus\n",
	       total, nr_live, to_bytes >> 20, mat_ms, mat_ms * 1000.0 / to_pages);
	printf("  in-kernel: faults=%llu objs=%llu refs_forwarded=%llu  (arena, arbitrary ref layout)\n",
	       (unsigned long long)skel->bss->kfa_faults,
	       (unsigned long long)skel->bss->kfa_objs,
	       (unsigned long long)skel->bss->kfa_refs);
	printf("%s\n", bad ? "FAIL" : "PASS");

	bpf_link__destroy(link);
	gc_kfixarena_bpf__destroy(skel);
	return bad ? 1 : 0;
}

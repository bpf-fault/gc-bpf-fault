// SPDX-License-Identifier: GPL-2.0-only
/*
 * Class B v2 capstone microbench: full Compressor-style in-kernel
 * materialization with VARIABLE-SIZE objects, offset-vector forward(), a
 * per-page first-source index, and a reference bitmap.  This retires the
 * remaining kernel-mechanism risk for live MMTk Compressor integration.
 *
 * Heap = array of u64 words.  Objects are variable-length runs (2..9 words);
 * ~1/3 are dead.  Compaction slides live words together (dead gaps removed),
 * preserving object runs.  References hold a 1-based old word index of a
 * referent object's first word.  All metadata lives in a BPF arena.
 */
#include "gc_common.h"
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "gc_kompress.skel.h"

#define BLOCK_WORDS    64
#define WORDS_PER_PAGE 512

int main(int argc, char **argv)
{
	long ps = sysconf(_SC_PAGESIZE);
	size_t total = argc > 1 ? strtoul(argv[1], NULL, 0) : 4u << 20; /* words */
	struct gc_kompress_bpf *skel;
	struct bpf_link *link;
	int bad = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	if (total > (1u << 24)) { fprintf(stderr, "total words > arena cap (16M)\n"); return 1; }

	uint64_t *val = calloc(total, sizeof(uint64_t));
	uint8_t  *liv = calloc(total, 1);
	uint8_t  *isref = calloc(total, 1);
	uint32_t *reftgt = calloc(total, sizeof(uint32_t)); /* referent old start word */

	/* Lay out variable-size objects. Record each object's start/size/live. */
	uint32_t *ostart = calloc(total, sizeof(uint32_t));
	uint8_t  *olive = calloc(total, 1);
	size_t nr_obj = 0;
	for (size_t w = 0; w < total; ) {
		size_t size = 2 + (w % 8);            /* 2..9 words */
		if (w + size > total) size = total - w;
		if (size == 0) break;
		int live = (nr_obj % 3 != 2);
		for (size_t k = 0; k < size; k++) liv[w + k] = live;
		val[w] = w + 1;                       /* header = 1-based old start */
		for (size_t k = 1; k < size; k++) val[w + k] = (w + 1) * 1000 + k;
		ostart[nr_obj] = w; olive[nr_obj] = live;
		nr_obj++; w += size;
	}

	/* Wire one reference per live object (its word[1]) to the next live obj. */
	for (size_t o = 0; o < nr_obj; o++) {
		if (!olive[o]) continue;
		uint32_t start = ostart[o];
		uint32_t size = (o + 1 < nr_obj ? ostart[o + 1] : total) - start;
		if (size < 2) continue;
		size_t t = o;
		for (size_t step = 1; step <= nr_obj; step++) {
			size_t cand = (o + step) % nr_obj;
			if (olive[cand]) { t = cand; break; }
		}
		isref[start + 1] = 1;
		reftgt[start + 1] = ostart[t];          /* 0-based old start word */
		val[start + 1] = ostart[t] + 1;         /* 1-based, handler subtracts 1 */
	}

	/* new word index (0-based) for each live word = live words before it. */
	uint32_t *newidx = calloc(total, sizeof(uint32_t));
	size_t nr_live = 0;
	for (size_t w = 0; w < total; w++) {
		newidx[w] = nr_live;
		if (liv[w]) nr_live++;
	}
	size_t to_bytes = ((nr_live * 8 + ps - 1) & ~(ps - 1));
	size_t to_pages = to_bytes / ps;
	uint64_t *to = alloc_anon_region(to_bytes, PROT_READ | PROT_WRITE);
	if (!to) return 1;

	skel = gc_kompress_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }
	skel->rodata->to_base = (unsigned long)to;
	skel->rodata->span_len = to_bytes;
	skel->rodata->total_words = total;
	skel->rodata->nr_live_words = nr_live;
	if (gc_kompress_bpf__load(skel)) { fprintf(stderr, "load failed (root? memlock?)\n"); return 1; }

	/* Populate arena: from_space words, livebits, refbits, offvec, first_src. */
	for (size_t w = 0; w < total; w++) {
		skel->arena->from_space[w] = val[w];
		if (liv[w])   skel->arena->livebits[w >> 6] |= (1ULL << (w & 63));
		if (isref[w]) skel->arena->refbits[w >> 6]  |= (1ULL << (w & 63));
	}
	uint32_t acc = 0;
	for (size_t b = 0; b * BLOCK_WORDS < total; b++) {
		skel->arena->offvec[b] = acc;            /* live words before block b */
		for (size_t k = 0; k < BLOCK_WORDS && b * BLOCK_WORDS + k < total; k++)
			if (liv[b * BLOCK_WORDS + k]) acc++;
	}
	/* first_src[page] = old word whose new index == page*512 */
	for (size_t w = 0; w < total; w++)
		if (liv[w] && (newidx[w] % WORDS_PER_PAGE) == 0)
			skel->arena->first_src[newidx[w] / WORDS_PER_PAGE] = w;

	link = bpf_map__attach_fault_ops(skel->maps.gc_kompress, to, to_bytes, 0);
	if (!link) { fprintf(stderr, "attach: %s\n", strerror(errno)); return 1; }

	uint64_t t0 = now_ns();
	for (size_t p = 0; p < to_pages; p++) {
		volatile uint64_t v = *(volatile uint64_t *)((char *)to + p * ps);
		(void)v;
	}
	double mat_ms = (now_ns() - t0) / 1e6;

	/* Verify every live word landed correctly (data preserved, refs forwarded). */
	for (size_t w = 0; w < total && bad < 10; w++) {
		if (!liv[w]) continue;
		uint64_t got = to[newidx[w]];
		uint64_t want;
		if (isref[w]) {
			uint32_t tgt = reftgt[w];           /* referent old start word */
			want = (uint64_t)to + (uint64_t)newidx[tgt] * 8;
		} else {
			want = val[w];
		}
		if (got != want) {
			fprintf(stderr, "word %zu (new %u)%s got %lx want %lx\n",
				w, newidx[w], isref[w] ? " REF" : "", got, want);
			bad++;
		}
	}

	printf("kompress: heap_words=%zu objs=%zu live_words=%zu to=%zuMB "
	       "materialize=%.3fms per-page=%.2fus\n",
	       total, nr_obj, nr_live, to_bytes >> 20, mat_ms, mat_ms * 1000.0 / to_pages);
	printf("  in-kernel: faults=%llu words=%llu refs_forwarded=%llu  "
	       "(variable objects, offset-vector forward, per-page index)\n",
	       (unsigned long long)skel->bss->kc_faults,
	       (unsigned long long)skel->bss->kc_words,
	       (unsigned long long)skel->bss->kc_refs);
	printf("%s\n", bad ? "FAIL" : "PASS");

	bpf_link__destroy(link);
	gc_kompress_bpf__destroy(skel);
	return bad ? 1 : 0;
}

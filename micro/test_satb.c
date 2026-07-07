// SPDX-License-Identifier: GPL-2.0-only
/*
 * Validate + cost the page-COW SATB primitive (gc_satb_ops):
 *
 *   1. Populate a heap region with generation-0 stamps.
 *   2. Arm it with the WP snapshot handler.
 *   3. Multi-threaded mutators overwrite a fraction of pages (gen-1).
 *   4. Verify: every written page has a snapshot holding EXACTLY the
 *      gen-0 content (the mark-start view); unwritten pages have no
 *      snapshot; live heap holds gen-1.  Report per-fault latency.
 *
 * This is the concurrent-marking mechanism: the marker reads the live
 * heap; SATB completeness comes from scanning snapshot pages.
 */
#include "gc_common.h"

#include <errno.h>
#include <pthread.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_satb_ops.skel.h"

struct mut_args {
	char *heap;
	size_t first, count;   /* page range to write */
	long page;
	uint64_t *lat;
};

static void *mutator(void *argp)
{
	struct mut_args *a = argp;
	for (size_t i = a->first; i < a->first + a->count; i++) {
		volatile uint64_t *p = (volatile uint64_t *)(a->heap + i * a->page);
		uint64_t t0 = now_ns();
		*p = i ^ 0x1111111100000000ULL;   /* gen-1 */
		a->lat[i] = now_ns() - t0;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t nr_pages = argc > 1 ? strtoul(argv[1], NULL, 0) : 65536;
	int nthreads = argc > 2 ? atoi(argv[2]) : 8;
	double frac = argc > 3 ? atof(argv[3]) : 0.5;
	size_t size = nr_pages * page;
	struct gc_satb_ops_bpf *skel;
	struct bpf_link *link;
	int bad = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	char *heap = alloc_anon_region(size, PROT_READ | PROT_WRITE);
	if (!heap)
		return 1;
	for (size_t i = 0; i < nr_pages; i++) {
		char *p = heap + i * page;
		memset(p, 0xCD, page);
		*(uint64_t *)p = i ^ 0xAAAA5555AAAA5555ULL;   /* gen-0 */
	}

	skel = gc_satb_ops_bpf__open();
	if (!skel)
		return 1;
	skel->rodata->heap_base = (unsigned long)heap;
	skel->rodata->span_len = size;
	size_t snapbm_off = size;                    /* pages then byte flags */
	size_t arena_bytes = size + nr_pages;
	arena_bytes = (arena_bytes + page - 1) & ~(size_t)(page - 1);
	if (bpf_map__set_max_entries(skel->maps.snap_arena, arena_bytes / page)) {
		fprintf(stderr, "arena size failed\n");
		return 1;
	}
	skel->bss->satb_count = 1;
	if (gc_satb_ops_bpf__load(skel)) {
		fprintf(stderr, "load failed (root?)\n");
		return 1;
	}
	skel->bss->snapbm_off = snapbm_off;
	uint64_t va = 1ull << 45;
	uint8_t *arena = mmap((void *)va, arena_bytes, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_FIXED,
			      bpf_map__fd(skel->maps.snap_arena), 0);
	if (arena == MAP_FAILED) {
		perror("mmap snap_arena");
		return 1;
	}
	/* Pre-populate: kernel-side arena stores to unpopulated pages are
	 * DROPPED (exception-table fixup, ~350us of fixups per snapshot).
	 * Touch every page from userspace so kernel PTEs exist.  In the GC
	 * this is the concurrent pre-arm phase's job each cycle. */
	uint64_t tp0 = now_ns();
	for (size_t i = 0; i < arena_bytes; i += page)
		arena[i] = 0;
	uint64_t tp1 = now_ns();
	printf("arena pre-touch: %.3fms\n", (tp1 - tp0) / 1e6);

	/* arm: WP registration over the heap */
	uint64_t t0 = now_ns();
	link = bpf_map__attach_fault_ops(skel->maps.gc_satb_ops, heap, size,
					 BPF_FAULT_FLAG_WP);
	uint64_t t1 = now_ns();
	if (!link) {
		fprintf(stderr, "attach WP failed: %s\n", strerror(errno));
		return 1;
	}
	/* registration arms the region; pages still need the WP marker */
	uint64_t t1b = now_ns();
	if (bpf_link_fault_cmd(bpf_link__fd(link), (uint64_t)heap, size,
			       BPF_FAULT_WP_ENABLE)) {
		perror("WP enable");
		return 1;
	}
	uint64_t t1c = now_ns();

	/* mutate a leading fraction of pages from N threads */
	size_t write_pages = (size_t)(nr_pages * frac);
	uint64_t *lat = calloc(nr_pages, sizeof(uint64_t));
	pthread_t th[64];
	struct mut_args args[64];
	size_t per = write_pages / nthreads;
	uint64_t t2 = now_ns();
	for (int t = 0; t < nthreads; t++) {
		args[t] = (struct mut_args){ heap, t * per,
			t == nthreads - 1 ? write_pages - t * per : per,
			page, lat };
		pthread_create(&th[t], NULL, mutator, &args[t]);
	}
	for (int t = 0; t < nthreads; t++)
		pthread_join(th[t], NULL);
	uint64_t t3 = now_ns();

	/* verify */
	uint8_t *snapbm = arena + snapbm_off;
	size_t snapped = 0;
	for (size_t i = 0; i < nr_pages; i++) {
		int bit = snapbm[i];
		if (i < write_pages) {
			uint64_t *snap = (uint64_t *)(arena + i * page);
			if (!bit) {
				if (bad < 5) fprintf(stderr, "page %zu: no snapshot\n", i);
				bad++;
			} else if (snap[0] != (i ^ 0xAAAA5555AAAA5555ULL) ||
				   ((uint8_t *)snap)[page - 1] != 0xCD) {
				if (bad < 5) fprintf(stderr, "page %zu: snapshot not gen-0\n", i);
				bad++;
			}
			if (*(volatile uint64_t *)(heap + i * page) !=
			    (i ^ 0x1111111100000000ULL)) {
				if (bad < 5) fprintf(stderr, "page %zu: live not gen-1\n", i);
				bad++;
			}
			snapped += bit;
		} else if (bit) {
			if (bad < 5) fprintf(stderr, "page %zu: spurious snapshot\n", i);
			bad++;
		}
	}

	struct lat_stats s = lat_compute(lat, write_pages);
	printf("satb: register(%zu pages)=%.3fms wp_enable=%.3fms mutate(%zu pages, %d thr)=%.3fms\n",
	       nr_pages, (t1 - t0) / 1e6, (t1c - t1b) / 1e6, write_pages,
	       nthreads, (t3 - t2) / 1e6);
	lat_print(&s);
	printf("snapshots=%llu read_fail=%llu snapped_bits=%zu\n",
	       (unsigned long long)skel->bss->satb_snapshots,
	       (unsigned long long)skel->bss->satb_read_fail, snapped);
	printf("RESULT test=satb pages=%zu threads=%d frac=%.2f %s\n",
	       nr_pages, nthreads, frac, bad ? "FAIL" : "PASS");
	bpf_link__destroy(link);
	gc_satb_ops_bpf__destroy(skel);
	return bad != 0;
}

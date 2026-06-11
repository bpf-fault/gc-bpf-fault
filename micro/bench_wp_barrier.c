// SPDX-License-Identifier: GPL-2.0-only
/*
 * Class A microbenchmark: page-protection write barrier for generational GC.
 *
 * Models the per-GC-cycle pattern of a Cracauer-style virtual-memory write
 * barrier replacing a compiled card/object barrier:
 *
 *   per cycle:
 *     1. protect  — write-protect the whole mature region ("end of GC")
 *     2. mutate   — T mutator threads each write a fraction of the pages in
 *                   a private slice; the first write to each page faults and
 *                   must be recorded as dirty
 *     3. collect  — read + clear the dirty-page set ("start of next GC")
 *
 * Backends:
 *   bpf   — bpf_fault WP: in-kernel eBPF handler sets a bit in an mmapable
 *           dirty bitmap and resumes the write
 *   uffd  — userfaultfd WP: dedicated handler thread marks dirty and resolves
 *           via UFFDIO_WRITEPROTECT (WP faults cannot use SIGBUS self-service)
 *   segv  — mprotect(PROT_READ) + SIGSEGV handler marks dirty + re-enables
 *   none  — unprotected writes (cost floor)
 *
 * Metrics: per-phase wall time, per-first-write fault latency distribution,
 * aggregate fault throughput, context switches.
 */
#include "gc_common.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/ioctl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_wp_ops.skel.h"

static long page_size;
static size_t nr_pages;
static int nr_threads;
static int nr_cycles;
static double write_frac;

static void *region;
static size_t region_size;

/* Userspace dirty bitmap for the uffd/segv backends. */
static _Atomic uint64_t *user_bitmap;
static size_t bitmap_words;

/* ------------------------------------------------------------------ */
/*  Backend interface                                                  */
/* ------------------------------------------------------------------ */

struct backend {
	const char *name;
	int (*setup)(void);
	int (*protect_all)(void);
	/* Returns number of dirty pages found, and clears the set. */
	size_t (*collect)(void);
	void (*teardown)(void);
};

/* ------------------------------------------------------------------ */
/*  Backend: bpf_fault WP                                              */
/* ------------------------------------------------------------------ */

static struct gc_wp_ops_bpf *bpf_skel;
static struct bpf_link *bpf_link;
static uint64_t *bpf_bitmap; /* mmaped dirty_bitmap map */
static size_t bpf_bitmap_map_size;

static int bpf_setup(void)
{
	bpf_skel = gc_wp_ops_bpf__open();
	if (!bpf_skel) {
		fprintf(stderr, "bpf: open skeleton failed\n");
		return -1;
	}
	bpf_skel->rodata->heap_base = (unsigned long)region;
	if (bpf_map__set_max_entries(bpf_skel->maps.dirty_bitmap,
				     bitmap_words)) {
		fprintf(stderr, "bpf: set_max_entries failed\n");
		return -1;
	}
	if (gc_wp_ops_bpf__load(bpf_skel)) {
		fprintf(stderr, "bpf: load failed\n");
		return -1;
	}

	bpf_link = bpf_map__attach_fault_ops(bpf_skel->maps.gc_wp_ops,
					     region, region_size,
					     BPF_FAULT_FLAG_WP);
	if (!bpf_link) {
		fprintf(stderr, "bpf: attach_fault_ops failed: %s\n",
			strerror(errno));
		return -1;
	}

	bpf_bitmap_map_size =
		(bitmap_words * sizeof(uint64_t) + page_size - 1) &
		~(page_size - 1);
	bpf_bitmap = mmap(NULL, bpf_bitmap_map_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED,
			  bpf_map__fd(bpf_skel->maps.dirty_bitmap), 0);
	if (bpf_bitmap == MAP_FAILED) {
		perror("bpf: mmap dirty_bitmap");
		bpf_bitmap = NULL;
		return -1;
	}
	return 0;
}

static int bpf_protect_all(void)
{
	if (bpf_link_fault_cmd(bpf_link__fd(bpf_link), (unsigned long)region,
			       region_size, BPF_FAULT_WP_ENABLE) < 0) {
		fprintf(stderr, "bpf: WP enable failed: %s\n",
			strerror(errno));
		return -1;
	}
	return 0;
}

static size_t bpf_collect(void)
{
	size_t dirty = 0;

	for (size_t w = 0; w < bitmap_words; w++) {
		if (bpf_bitmap[w]) {
			dirty += __builtin_popcountll(bpf_bitmap[w]);
			bpf_bitmap[w] = 0;
		}
	}
	return dirty;
}

static void bpf_teardown(void)
{
	if (bpf_bitmap)
		munmap(bpf_bitmap, bpf_bitmap_map_size);
	if (bpf_link)
		bpf_link__destroy(bpf_link);
	if (bpf_skel)
		gc_wp_ops_bpf__destroy(bpf_skel);
	bpf_bitmap = NULL;
	bpf_link = NULL;
	bpf_skel = NULL;
}

/* ------------------------------------------------------------------ */
/*  Userspace bitmap helpers (uffd + segv backends)                    */
/* ------------------------------------------------------------------ */

static inline void user_mark_dirty(unsigned long addr)
{
	size_t idx = (addr - (unsigned long)region) / page_size;

	atomic_fetch_or_explicit(&user_bitmap[idx >> 6], 1ULL << (idx & 63),
				 memory_order_relaxed);
}

static size_t user_collect(void)
{
	size_t dirty = 0;

	for (size_t w = 0; w < bitmap_words; w++) {
		uint64_t v = atomic_load_explicit(&user_bitmap[w],
						  memory_order_relaxed);
		if (v) {
			dirty += __builtin_popcountll(v);
			atomic_store_explicit(&user_bitmap[w], 0,
					      memory_order_relaxed);
		}
	}
	return dirty;
}

/* ------------------------------------------------------------------ */
/*  Backend: userfaultfd WP + handler thread                           */
/* ------------------------------------------------------------------ */

static int uffd = -1;
static pthread_t uffd_thread;
static volatile int uffd_done;

static void *uffd_handler_fn(void *arg)
{
	for (;;) {
		struct pollfd pfd = { .fd = uffd, .events = POLLIN };
		struct uffd_msg msg;
		ssize_t n;

		if (poll(&pfd, 1, 50) <= 0) {
			if (uffd_done)
				break;
			continue;
		}
		n = read(uffd, &msg, sizeof(msg));
		if (n <= 0) {
			if (uffd_done)
				break;
			continue;
		}
		if (msg.event != UFFD_EVENT_PAGEFAULT)
			continue;

		unsigned long addr = msg.arg.pagefault.address &
				     ~(page_size - 1);
		struct uffdio_writeprotect wp = {
			.range = { .start = addr, .len = page_size },
			.mode = 0,
		};

		user_mark_dirty(addr);
		if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) < 0 &&
		    errno != ENOENT)
			perror("UFFDIO_WRITEPROTECT resolve");
	}
	return NULL;
}

static int uffd_setup(void)
{
	struct uffdio_api api = {
		.api = UFFD_API,
		.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP,
	};
	struct uffdio_register reg = {
		.range = { .start = (unsigned long)region,
			   .len = region_size },
		.mode = UFFDIO_REGISTER_MODE_WP,
	};

	uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0) {
		perror("userfaultfd");
		return -1;
	}
	if (ioctl(uffd, UFFDIO_API, &api) < 0) {
		perror("UFFDIO_API");
		return -1;
	}
	if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0) {
		perror("UFFDIO_REGISTER");
		return -1;
	}
	uffd_done = 0;
	pthread_create(&uffd_thread, NULL, uffd_handler_fn, NULL);
	return 0;
}

static int uffd_protect_all(void)
{
	struct uffdio_writeprotect wp = {
		.range = { .start = (unsigned long)region,
			   .len = region_size },
		.mode = UFFDIO_WRITEPROTECT_MODE_WP,
	};

	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) < 0) {
		perror("UFFDIO_WRITEPROTECT enable");
		return -1;
	}
	return 0;
}

static void uffd_teardown(void)
{
	if (uffd < 0)
		return;
	uffd_done = 1;
	pthread_join(uffd_thread, NULL);
	close(uffd);
	uffd = -1;
}

/* ------------------------------------------------------------------ */
/*  Backend: mprotect + SIGSEGV                                        */
/* ------------------------------------------------------------------ */

static struct sigaction segv_old_sa;

static void segv_handler(int sig, siginfo_t *si, void *ctx)
{
	unsigned long addr = (unsigned long)si->si_addr & ~(page_size - 1);

	user_mark_dirty(addr);
	mprotect((void *)addr, page_size, PROT_READ | PROT_WRITE);
}

static int segv_setup(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSEGV, &sa, &segv_old_sa) < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

static int segv_protect_all(void)
{
	if (mprotect(region, region_size, PROT_READ) < 0) {
		perror("mprotect(PROT_READ)");
		return -1;
	}
	return 0;
}

static void segv_teardown(void)
{
	mprotect(region, region_size, PROT_READ | PROT_WRITE);
	sigaction(SIGSEGV, &segv_old_sa, NULL);
}

/* ------------------------------------------------------------------ */
/*  Backend: none (floor)                                              */
/* ------------------------------------------------------------------ */

static int noop_setup(void) { return 0; }
static int noop_protect(void) { return 0; }
static size_t noop_collect(void) { return 0; }
static void noop_teardown(void) {}

static struct backend backends[] = {
	{ "bpf", bpf_setup, bpf_protect_all, bpf_collect, bpf_teardown },
	{ "uffd", uffd_setup, uffd_protect_all, user_collect, uffd_teardown },
	{ "segv", segv_setup, segv_protect_all, user_collect, segv_teardown },
	{ "none", noop_setup, noop_protect, noop_collect, noop_teardown },
};

/* ------------------------------------------------------------------ */
/*  Mutator threads                                                    */
/* ------------------------------------------------------------------ */

struct mutator {
	pthread_t tid;
	int id;
	size_t slice_start;	/* first page of this thread's slice */
	size_t slice_pages;
	size_t *perm;		/* shuffled page order within slice */
	size_t writes;		/* writes (= distinct pages) per cycle */
	uint64_t *lat;		/* writes entries, this cycle */
};

static pthread_barrier_t start_barrier, end_barrier;
static volatile int mutators_exit;

static void *mutator_fn(void *arg)
{
	struct mutator *m = arg;

	for (;;) {
		pthread_barrier_wait(&start_barrier);
		if (mutators_exit)
			break;

		for (size_t k = 0; k < m->writes; k++) {
			volatile char *p = (volatile char *)region +
				(m->slice_start + m->perm[k]) * page_size;
			uint64_t before = now_ns();
			*p = 'W';
			m->lat[k] = now_ns() - before;
		}

		pthread_barrier_wait(&end_barrier);
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/*  Benchmark driver                                                   */
/* ------------------------------------------------------------------ */

static void populate_pages(void)
{
	for (size_t i = 0; i < nr_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		*p = 'P';
	}
}

static int run_backend(struct backend *b)
{
	size_t slice = nr_pages / nr_threads;
	size_t writes = (size_t)(write_frac * slice);
	size_t total_writes = writes * nr_threads;
	struct mutator *muts;
	uint64_t *all_lat;
	size_t all_n = 0;
	double protect_ms = 0, mutate_ms = 0, collect_ms = 0;
	long csw_before, csw_after;
	int ret = -1;

	if (!writes) {
		fprintf(stderr, "no writes per thread; increase -n or -f\n");
		return -1;
	}

	printf("=== backend=%s pages=%zu threads=%d cycles=%d frac=%.2f (%zu writes/cycle) ===\n",
	       b->name, nr_pages, nr_threads, nr_cycles, write_frac,
	       total_writes);
	fflush(stdout);

	region_size = nr_pages * page_size;
	region = alloc_anon_region(region_size, PROT_READ | PROT_WRITE);
	if (!region)
		return -1;
	populate_pages();

	bitmap_words = (nr_pages + 63) / 64;
	user_bitmap = calloc(bitmap_words, sizeof(uint64_t));

	if (b->setup())
		goto out;

	muts = calloc(nr_threads, sizeof(*muts));
	all_lat = calloc(nr_cycles * total_writes, sizeof(uint64_t));

	pthread_barrier_init(&start_barrier, NULL, nr_threads + 1);
	pthread_barrier_init(&end_barrier, NULL, nr_threads + 1);
	mutators_exit = 0;

	for (int t = 0; t < nr_threads; t++) {
		struct mutator *m = &muts[t];

		m->id = t;
		m->slice_start = t * slice;
		m->slice_pages = slice;
		m->perm = calloc(slice, sizeof(size_t));
		m->writes = writes;
		m->lat = calloc(writes, sizeof(uint64_t));
		pthread_create(&m->tid, NULL, mutator_fn, m);
	}

	csw_before = context_switches();

	for (int c = 0; c < nr_cycles; c++) {
		uint64_t t0, t1, t2, t3;
		size_t dirty;

		/* New page order each cycle so different pages fault. */
		for (int t = 0; t < nr_threads; t++)
			shuffle_pages(muts[t].perm, slice,
				      0x9e3779b9 * (c + 1) + muts[t].id);

		t0 = now_ns();
		if (b->protect_all())
			goto out_threads;
		t1 = now_ns();

		pthread_barrier_wait(&start_barrier); /* mutate */
		pthread_barrier_wait(&end_barrier);
		t2 = now_ns();

		dirty = b->collect();
		t3 = now_ns();

		for (int t = 0; t < nr_threads; t++) {
			memcpy(all_lat + all_n, muts[t].lat,
			       writes * sizeof(uint64_t));
			all_n += writes;
		}

		protect_ms += (t1 - t0) / 1e6;
		mutate_ms += (t2 - t1) / 1e6;
		collect_ms += (t3 - t2) / 1e6;

		printf("  cycle %d: protect=%.3fms mutate=%.3fms collect=%.3fms dirty=%zu/%zu%s\n",
		       c, (t1 - t0) / 1e6, (t2 - t1) / 1e6, (t3 - t2) / 1e6,
		       dirty, total_writes,
		       (strcmp(b->name, "none") && dirty != total_writes) ?
		       " MISMATCH" : "");
	}

	csw_after = context_switches();

	{
		struct lat_stats s = lat_compute(all_lat, all_n);
		double mutate_avg = mutate_ms / nr_cycles;

		lat_print(&s);
		printf("    Context switches during run: %ld\n",
		       csw_after - csw_before);
		printf("RESULT bench=wp_barrier backend=%s threads=%d pages=%zu cycles=%d frac=%.2f "
		       "protect_ms=%.3f mutate_ms=%.3f collect_ms=%.3f faults_per_cycle=%zu "
		       "lat_avg=%lu lat_p50=%lu lat_p99=%lu lat_p999=%lu lat_max=%lu csw=%ld\n",
		       b->name, nr_threads, nr_pages, nr_cycles, write_frac,
		       protect_ms / nr_cycles, mutate_avg,
		       collect_ms / nr_cycles, total_writes,
		       s.avg, s.p50, s.p99, s.p999, s.max,
		       csw_after - csw_before);
	}
	ret = 0;

out_threads:
	mutators_exit = 1;
	pthread_barrier_wait(&start_barrier);
	for (int t = 0; t < nr_threads; t++) {
		pthread_join(muts[t].tid, NULL);
		free(muts[t].perm);
		free(muts[t].lat);
	}
	pthread_barrier_destroy(&start_barrier);
	pthread_barrier_destroy(&end_barrier);
	free(muts);
	free(all_lat);
out:
	b->teardown();
	free((void *)user_bitmap);
	user_bitmap = NULL;
	munmap(region, region_size);
	region = NULL;
	printf("\n");
	return ret;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-n pages] [-t threads] [-c cycles] [-f frac] [-b bpf|uffd|segv|none|all]\n",
		prog);
}

int main(int argc, char **argv)
{
	const char *which = "all";
	int opt;

	page_size = sysconf(_SC_PAGESIZE);
	nr_pages = 131072; /* 512 MiB */
	nr_threads = 8;
	nr_cycles = 5;
	write_frac = 0.25;

	while ((opt = getopt(argc, argv, "n:t:c:f:b:h")) != -1) {
		switch (opt) {
		case 'n': nr_pages = strtoul(optarg, NULL, 0); break;
		case 't': nr_threads = atoi(optarg); break;
		case 'c': nr_cycles = atoi(optarg); break;
		case 'f': write_frac = atof(optarg); break;
		case 'b': which = optarg; break;
		default: usage(argv[0]); return opt == 'h' ? 0 : 1;
		}
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	for (size_t i = 0; i < sizeof(backends) / sizeof(backends[0]); i++) {
		if (strcmp(which, "all") && strcmp(which, backends[i].name))
			continue;
		if (run_backend(&backends[i]))
			fprintf(stderr, "backend %s failed\n",
				backends[i].name);
	}
	return 0;
}

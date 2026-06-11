// SPDX-License-Identifier: GPL-2.0-only
/*
 * Class B microbenchmark: concurrent-compaction page materialization.
 *
 * Models the post-flip window of an ART/Compressor-style concurrent
 * compacting GC: page contents are staged in a populated from-space
 * (representing the userspace-compacted page), to-space is empty and
 * fault-registered, and pages are materialized on first access.
 * Mutator threads collectively touch every to-space page exactly once
 * (shared shuffled permutation); an optional GC thread sweeps linearly,
 * racing with the mutators (-g), as the real collector does.
 *
 * Backends:
 *   bpf         — bpf_fault missing fault: eBPF handler copies the staged
 *                 page directly into the kernel-provided page (zero-copy,
 *                 no signal, no ioctl)
 *   uffd_sigbus — ART production policy: UFFD_FEATURE_SIGBUS; the faulting
 *                 mutator's SIGBUS handler issues UFFDIO_COPY from the
 *                 staged page
 *   uffd_thread — handler thread reads fault events and UFFDIO_COPYs
 *   segv        — PROT_NONE to-space; SIGSEGV handler mprotects the page
 *                 and copies. NOT atomic: concurrent readers can observe
 *                 zeroes between mprotect and copy (the classic flaw that
 *                 motivates uffd/bpf_fault install semantics); per-page
 *                 state CAS keeps the benchmark itself converging.
 *
 * Metrics: per-access latency distribution (every page's first toucher eats
 * a fault), time until all pages are materialized, fault counts, context
 * switches.
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

#include "gc_compact_ops.skel.h"

static long page_size;
static size_t nr_pages;
static int nr_threads;
static int with_gc_thread;

static void *from_space;
static void *to_space;
static size_t region_size;

/* segv backend page states: 0=missing 1=copying 2=done */
static _Atomic uint8_t *segv_state;

/* ------------------------------------------------------------------ */
/*  Backend interface                                                  */
/* ------------------------------------------------------------------ */

struct cbackend {
	const char *name;
	int (*setup)(void);	/* prepare to_space, ready for access */
	/* GC-thread materialization of one page (need not fault). */
	void (*gc_materialize)(size_t page);
	void (*teardown)(void);
};

/* ------------------------------------------------------------------ */
/*  Backend: bpf_fault missing                                         */
/* ------------------------------------------------------------------ */

static struct gc_compact_ops_bpf *bpf_skel;
static struct bpf_link *bpf_link;

static int bpf_setup(void)
{
	to_space = alloc_anon_region(region_size, PROT_READ | PROT_WRITE);
	if (!to_space)
		return -1;

	bpf_skel = gc_compact_ops_bpf__open();
	if (!bpf_skel) {
		fprintf(stderr, "bpf: open skeleton failed\n");
		return -1;
	}
	bpf_skel->rodata->to_base = (unsigned long)to_space;
	bpf_skel->rodata->from_base = (unsigned long)from_space;
	bpf_skel->rodata->region_len = region_size;
	if (gc_compact_ops_bpf__load(bpf_skel)) {
		fprintf(stderr, "bpf: load failed\n");
		return -1;
	}
	bpf_link = bpf_map__attach_fault_ops(bpf_skel->maps.gc_compact_ops,
					     to_space, region_size, 0);
	if (!bpf_link) {
		fprintf(stderr, "bpf: attach_fault_ops failed: %s\n",
			strerror(errno));
		return -1;
	}
	return 0;
}

static void bpf_gc_materialize(size_t page)
{
	/* Touch the page: the in-kernel handler installs it. */
	volatile char *p = (volatile char *)to_space + page * page_size;
	(void)*p;
}

static void bpf_teardown(void)
{
	if (bpf_link)
		bpf_link__destroy(bpf_link);
	if (bpf_skel)
		gc_compact_ops_bpf__destroy(bpf_skel);
	bpf_link = NULL;
	bpf_skel = NULL;
}

/* ------------------------------------------------------------------ */
/*  uffd shared bits                                                   */
/* ------------------------------------------------------------------ */

static int uffd = -1;

static void uffd_copy_page(size_t page)
{
	struct uffdio_copy copy = {
		.dst = (unsigned long)to_space + page * page_size,
		.src = (unsigned long)from_space + page * page_size,
		.len = page_size,
		.mode = 0,
	};

	if (ioctl(uffd, UFFDIO_COPY, &copy) < 0 &&
	    errno != EEXIST && errno != ENOENT)
		perror("UFFDIO_COPY");
}

static int uffd_open(unsigned int features)
{
	struct uffdio_api api = { .api = UFFD_API, .features = features };
	struct uffdio_register reg = {
		.range = { .start = (unsigned long)to_space,
			   .len = region_size },
		.mode = UFFDIO_REGISTER_MODE_MISSING,
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
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Backend: uffd + SIGBUS self-service (ART policy)                   */
/* ------------------------------------------------------------------ */

static void sigbus_handler(int sig, siginfo_t *si, void *ctx)
{
	size_t page = ((unsigned long)si->si_addr -
		       (unsigned long)to_space) / page_size;

	uffd_copy_page(page);
}

static struct sigaction sigbus_old_sa;

static int uffd_sigbus_setup(void)
{
	struct sigaction sa;

	to_space = alloc_anon_region(region_size, PROT_READ | PROT_WRITE);
	if (!to_space)
		return -1;
	if (uffd_open(UFFD_FEATURE_SIGBUS))
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sigbus_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGBUS, &sa, &sigbus_old_sa) < 0) {
		perror("sigaction(SIGBUS)");
		return -1;
	}
	return 0;
}

static void uffd_sigbus_teardown(void)
{
	sigaction(SIGBUS, &sigbus_old_sa, NULL);
	if (uffd >= 0)
		close(uffd);
	uffd = -1;
}

/* ------------------------------------------------------------------ */
/*  Backend: uffd + handler thread                                     */
/* ------------------------------------------------------------------ */

static pthread_t uffd_hthread;
static volatile int uffd_hdone;

static void *uffd_handler_fn(void *arg)
{
	for (;;) {
		struct pollfd pfd = { .fd = uffd, .events = POLLIN };
		struct uffd_msg msg;
		ssize_t n;

		if (poll(&pfd, 1, 50) <= 0) {
			if (uffd_hdone)
				break;
			continue;
		}
		n = read(uffd, &msg, sizeof(msg));
		if (n <= 0) {
			if (uffd_hdone)
				break;
			continue;
		}
		if (msg.event != UFFD_EVENT_PAGEFAULT)
			continue;

		size_t page = (msg.arg.pagefault.address -
			       (unsigned long)to_space) / page_size;
		uffd_copy_page(page);
	}
	return NULL;
}

static int uffd_thread_setup(void)
{
	to_space = alloc_anon_region(region_size, PROT_READ | PROT_WRITE);
	if (!to_space)
		return -1;
	if (uffd_open(0))
		return -1;
	uffd_hdone = 0;
	pthread_create(&uffd_hthread, NULL, uffd_handler_fn, NULL);
	return 0;
}

static void uffd_thread_teardown(void)
{
	if (uffd < 0)
		return;
	uffd_hdone = 1;
	pthread_join(uffd_hthread, NULL);
	close(uffd);
	uffd = -1;
}

/* ------------------------------------------------------------------ */
/*  Backend: mprotect + SIGSEGV                                        */
/* ------------------------------------------------------------------ */

static struct sigaction segv_old_sa;

static void segv_materialize(size_t page)
{
	uint8_t expected = 0;

	if (atomic_compare_exchange_strong(&segv_state[page], &expected, 1)) {
		void *dst = (char *)to_space + page * page_size;

		mprotect(dst, page_size, PROT_READ | PROT_WRITE);
		memcpy(dst, (char *)from_space + page * page_size, page_size);
		atomic_store(&segv_state[page], 2);
	} else {
		while (atomic_load_explicit(&segv_state[page],
					    memory_order_acquire) != 2)
			;
	}
}

static void segv_compact_handler(int sig, siginfo_t *si, void *ctx)
{
	size_t page = ((unsigned long)si->si_addr -
		       (unsigned long)to_space) / page_size;

	segv_materialize(page);
}

static int segv_setup(void)
{
	struct sigaction sa;

	to_space = alloc_anon_region(region_size, PROT_NONE);
	if (!to_space)
		return -1;
	segv_state = calloc(nr_pages, sizeof(uint8_t));

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_compact_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSEGV, &sa, &segv_old_sa) < 0) {
		perror("sigaction(SIGSEGV)");
		return -1;
	}
	return 0;
}

static void segv_teardown(void)
{
	sigaction(SIGSEGV, &segv_old_sa, NULL);
	free((void *)segv_state);
	segv_state = NULL;
}

static struct cbackend cbackends[] = {
	{ "bpf", bpf_setup, bpf_gc_materialize, bpf_teardown },
	{ "uffd_sigbus", uffd_sigbus_setup, uffd_copy_page,
	  uffd_sigbus_teardown },
	{ "uffd_thread", uffd_thread_setup, uffd_copy_page,
	  uffd_thread_teardown },
	{ "segv", segv_setup, segv_materialize, segv_teardown },
};

/* ------------------------------------------------------------------ */
/*  Mutators and GC thread                                             */
/* ------------------------------------------------------------------ */

static size_t *page_perm;
static _Atomic size_t next_idx;
static pthread_barrier_t go_barrier;

struct cmutator {
	pthread_t tid;
	uint64_t *lat;
	size_t n_lat;
	uint64_t sum;	/* checksum to defeat optimization */
};

static void *cmutator_fn(void *arg)
{
	struct cmutator *m = arg;

	pthread_barrier_wait(&go_barrier);

	for (;;) {
		size_t k = atomic_fetch_add(&next_idx, 1);

		if (k >= nr_pages)
			break;

		volatile uint64_t *p = (volatile uint64_t *)
			((char *)to_space + page_perm[k] * page_size);
		uint64_t before = now_ns();
		uint64_t v = *p;
		m->lat[m->n_lat++] = now_ns() - before;
		m->sum += v;
	}
	return NULL;
}

struct gc_sweep {
	pthread_t tid;
	struct cbackend *b;
	uint64_t sweep_ns;
};

static void *gc_sweep_fn(void *arg)
{
	struct gc_sweep *g = arg;
	uint64_t t0;

	pthread_barrier_wait(&go_barrier);
	t0 = now_ns();
	for (size_t i = 0; i < nr_pages; i++)
		g->b->gc_materialize(i);
	g->sweep_ns = now_ns() - t0;
	return NULL;
}

/* ------------------------------------------------------------------ */
/*  Driver                                                             */
/* ------------------------------------------------------------------ */

static int verify_pages(void)
{
	int bad = 0;

	for (size_t i = 0; i < nr_pages; i++) {
		uint64_t *p = (uint64_t *)((char *)to_space + i * page_size);

		if (*p != i) {
			if (bad < 5)
				fprintf(stderr,
					"  VERIFY FAIL page %zu: got %lu\n",
					i, *p);
			bad++;
		}
	}
	return bad;
}

static int run_cbackend(struct cbackend *b)
{
	struct cmutator *muts;
	struct gc_sweep gc = { .b = b };
	uint64_t *all_lat;
	size_t all_n = 0;
	uint64_t t_start, t_end;
	long csw_before, csw_after;
	int parties = nr_threads + 1 + (with_gc_thread ? 1 : 0);
	int bad, ret = -1;

	printf("=== backend=%s pages=%zu threads=%d gc_thread=%d ===\n",
	       b->name, nr_pages, nr_threads, with_gc_thread);
	fflush(stdout);

	if (b->setup())
		goto out;

	muts = calloc(nr_threads, sizeof(*muts));
	all_lat = calloc(nr_pages, sizeof(uint64_t));
	atomic_store(&next_idx, 0);

	pthread_barrier_init(&go_barrier, NULL, parties);

	for (int t = 0; t < nr_threads; t++) {
		muts[t].lat = calloc(nr_pages, sizeof(uint64_t));
		pthread_create(&muts[t].tid, NULL, cmutator_fn, &muts[t]);
	}
	if (with_gc_thread)
		pthread_create(&gc.tid, NULL, gc_sweep_fn, &gc);

	csw_before = context_switches();
	t_start = now_ns();
	pthread_barrier_wait(&go_barrier); /* go */

	for (int t = 0; t < nr_threads; t++)
		pthread_join(muts[t].tid, NULL);
	t_end = now_ns();
	if (with_gc_thread)
		pthread_join(gc.tid, NULL);
	csw_after = context_switches();

	for (int t = 0; t < nr_threads; t++) {
		memcpy(all_lat + all_n, muts[t].lat,
		       muts[t].n_lat * sizeof(uint64_t));
		all_n += muts[t].n_lat;
		free(muts[t].lat);
	}

	bad = verify_pages();

	{
		struct lat_stats s = lat_compute(all_lat, all_n);
		double total_ms = (t_end - t_start) / 1e6;

		lat_print(&s);
		printf("    Mutator phase: %.3f ms (%zu accesses)%s\n",
		       total_ms, all_n, bad ? " VERIFY-FAILED" : "");
		if (with_gc_thread)
			printf("    GC sweep: %.3f ms\n", gc.sweep_ns / 1e6);
		printf("RESULT bench=compact backend=%s threads=%d pages=%zu gc=%d "
		       "total_ms=%.3f sweep_ms=%.3f lat_avg=%lu lat_p50=%lu "
		       "lat_p99=%lu lat_p999=%lu lat_max=%lu csw=%ld bad=%d\n",
		       b->name, nr_threads, nr_pages, with_gc_thread,
		       total_ms, with_gc_thread ? gc.sweep_ns / 1e6 : 0.0,
		       s.avg, s.p50, s.p99, s.p999, s.max,
		       csw_after - csw_before, bad);
	}

	pthread_barrier_destroy(&go_barrier);
	free(muts);
	free(all_lat);
	ret = 0;
out:
	b->teardown();
	if (to_space) {
		munmap(to_space, region_size);
		to_space = NULL;
	}
	printf("\n");
	return ret;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-n pages] [-t threads] [-g] [-b bpf|uffd_sigbus|uffd_thread|segv|all]\n",
		prog);
}

int main(int argc, char **argv)
{
	const char *which = "all";
	int opt;

	page_size = sysconf(_SC_PAGESIZE);
	nr_pages = 131072; /* 512 MiB */
	nr_threads = 8;
	with_gc_thread = 0;

	while ((opt = getopt(argc, argv, "n:t:gb:h")) != -1) {
		switch (opt) {
		case 'n': nr_pages = strtoul(optarg, NULL, 0); break;
		case 't': nr_threads = atoi(optarg); break;
		case 'g': with_gc_thread = 1; break;
		case 'b': which = optarg; break;
		default: usage(argv[0]); return opt == 'h' ? 0 : 1;
		}
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	region_size = nr_pages * page_size;

	/* Stage the from-space: page i stamped with i. */
	from_space = alloc_anon_region(region_size, PROT_READ | PROT_WRITE);
	if (!from_space)
		return 1;
	for (size_t i = 0; i < nr_pages; i++) {
		char *p = (char *)from_space + i * page_size;

		memset(p, 0xC3, page_size);
		*(uint64_t *)p = i;
	}

	page_perm = calloc(nr_pages, sizeof(size_t));
	shuffle_pages(page_perm, nr_pages, 0xdeadbeef);

	for (size_t i = 0; i < sizeof(cbackends) / sizeof(cbackends[0]); i++) {
		if (strcmp(which, "all") && strcmp(which, cbackends[i].name))
			continue;
		if (run_cbackend(&cbackends[i]))
			fprintf(stderr, "backend %s failed\n",
				cbackends[i].name);
	}
	return 0;
}

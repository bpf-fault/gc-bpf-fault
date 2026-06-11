// SPDX-License-Identifier: GPL-2.0-only
/*
 * C shim exposing bpf_fault WP dirty tracking to MMTk (dlopen'ed by
 * mmtk-core's dirty_track module).  Wraps skeleton load/attach, multi-region
 * registration, range write-protect, and the mmaped dirty bitmap.
 *
 * The eBPF program (gc_wp_ops.bpf.c, shared with micro/) sets a bit in the
 * dirty bitmap on each WP fault and allows the write.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_wp_ops.skel.h"
#include "../micro/gc_common.h"

static struct gc_wp_ops_bpf *skel;
static struct bpf_link *wp_link;
static uint64_t *bitmap;
static unsigned long span_start;
static unsigned long span_len;

int gcbpf_init(uint64_t start, uint64_t len)
{
	size_t words = (len / 4096 + 63) / 64;
	size_t map_bytes;
	long page = sysconf(_SC_PAGESIZE);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = gc_wp_ops_bpf__open();
	if (!skel) {
		fprintf(stderr, "gcbpf: open skeleton failed\n");
		return -1;
	}
	skel->rodata->heap_base = start;
	if (bpf_map__set_max_entries(skel->maps.dirty_bitmap, words)) {
		fprintf(stderr, "gcbpf: set_max_entries failed\n");
		return -1;
	}
	if (gc_wp_ops_bpf__load(skel)) {
		fprintf(stderr, "gcbpf: load failed (need CAP_BPF / root)\n");
		return -1;
	}

	map_bytes = (words * sizeof(uint64_t) + page - 1) & ~(page - 1);
	bitmap = mmap(NULL, map_bytes, PROT_READ | PROT_WRITE, MAP_SHARED,
		      bpf_map__fd(skel->maps.dirty_bitmap), 0);
	if (bitmap == MAP_FAILED) {
		perror("gcbpf: mmap dirty_bitmap");
		bitmap = NULL;
		return -1;
	}

	span_start = start;
	span_len = len;
	return 0;
}

int gcbpf_register(uint64_t start, uint64_t len)
{
	if (!skel)
		return -1;
	if (!wp_link) {
		wp_link = bpf_map__attach_fault_ops(skel->maps.gc_wp_ops,
						 (void *)start, len,
						 BPF_FAULT_FLAG_WP);
		if (!wp_link) {
			perror("gcbpf: attach_fault_ops");
			return -1;
		}
		return 0;
	}
	if (bpf_link__fault_register(bpf_link__fd(wp_link), start, len)) {
		perror("gcbpf: fault_register");
		return -1;
	}
	return 0;
}

int gcbpf_wp(uint64_t start, uint64_t len, int enable)
{
	if (!wp_link)
		return -1;
	if (bpf_link_fault_cmd(bpf_link__fd(wp_link), start, len,
			       enable ? BPF_FAULT_WP_ENABLE : 0)) {
		perror("gcbpf: writeprotect");
		return -1;
	}
	return 0;
}

uint64_t *gcbpf_bitmap(void)
{
	return bitmap;
}

uint64_t gcbpf_fault_count(void)
{
	return skel ? skel->bss->wp_fault_count : 0;
}

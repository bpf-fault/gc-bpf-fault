// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kernel-mode writes (copy_to_user via read(2)) into WP-armed pages:
 * does the in-kernel WP resolution preserve the REST of the page?
 *
 * The JVM scenario: file I/O reads into a heap byte[] whose page also
 * holds neighboring objects' reference fields.  If the kernel-side WP
 * fault path resolves destructively (page replacement/zeroing beyond the
 * copy range) those refs are wiped -> dangling references, exactly the
 * corruption observed with a NO-OP WP handler under Java.
 */
#include "gc_common.h"

#include <errno.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "gc_wp_ops.skel.h"

int main(void)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t size = 16 * page;
	struct gc_wp_ops_bpf *skel;
	struct bpf_link *link;
	int bad = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	char *heap = alloc_anon_region(size, PROT_READ | PROT_WRITE);
	if (!heap)
		return 1;
	/* sentinels everywhere */
	for (size_t i = 0; i < size / 8; i++)
		((uint64_t *)heap)[i] = 0xA5A5A5A5A5A5A5A5ULL ^ i;

	/* a scratch file with a known pattern */
	char path[] = "/tmp/wpuaccessXXXXXX";
	int fd = mkstemp(path);
	char fbuf[4096];
	memset(fbuf, 0x3C, sizeof(fbuf));
	for (int i = 0; i < 4; i++)
		if (write(fd, fbuf, sizeof(fbuf)) != sizeof(fbuf))
			return 1;

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
	if (bpf_link_fault_cmd(bpf_link__fd(link), (uint64_t)heap, size,
			       BPF_FAULT_WP_ENABLE)) {
		perror("WP enable");
		return 1;
	}

	/* read(2) into the MIDDLE of armed pages: 1000 bytes at odd offset,
	 * crossing a page boundary; repeat over several target spots */
	for (int spot = 0; spot < 8; spot++) {
		char *dst = heap + spot * 2 * page + 3000; /* crosses boundary */
		if (lseek(fd, 0, SEEK_SET) < 0)
			return 1;
		ssize_t n = read(fd, dst, 1000);
		if (n != 1000) {
			printf("read returned %zd errno=%d at spot %d\n",
			       n, errno, spot);
			bad++;
			continue;
		}
		for (int i = 0; i < 1000; i++)
			if ((unsigned char)dst[i] != 0x3C) {
				printf("spot %d: copy content wrong at %d\n", spot, i);
				bad++;
				break;
			}
	}
	/* verify EVERY sentinel outside the written ranges survived */
	for (size_t i = 0; i < size / 8; i++) {
		char *addr = (char *)&((uint64_t *)heap)[i];
		int inside = 0;
		for (int spot = 0; spot < 8; spot++) {
			char *dst = heap + spot * 2 * page + 3000;
			if (addr + 8 > dst && addr < dst + 1000)
				inside = 1;
		}
		if (inside)
			continue;
		if (((uint64_t *)heap)[i] != (0xA5A5A5A5A5A5A5A5ULL ^ i)) {
			if (bad < 12)
				printf("sentinel wiped at +%zx: %llx\n", i * 8,
				       (unsigned long long)((uint64_t *)heap)[i]);
			bad++;
		}
	}
	printf("RESULT test=wp_uaccess %s (bad=%d)\n",
	       bad ? "FAIL(KERNEL BUG)" : "PASS", bad);
	close(fd);
	unlink(path);
	bpf_link__destroy(link);
	gc_wp_ops_bpf__destroy(skel);
	return bad != 0;
}

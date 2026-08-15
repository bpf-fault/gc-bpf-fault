/* Standalone verifier check: open+load gc_b0_ops with realistic map sizes.
 * Exit 0 = program verifies; nonzero = load failure (verifier log on stderr). */
#include <bpf/bpf.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include "gc_b0_ops.skel.h"

int main(void)
{
	size_t span_len = 768ul << 20, page = 4096, pages = span_len / page;
	struct gc_b0_ops_bpf *s = gc_b0_ops_bpf__open();
	if (!s) { fprintf(stderr, "open failed\n"); return 1; }
	s->rodata->space_base = 0x40000000ul;
	s->rodata->arena_base = 0x100000000ul;
	s->rodata->span_len = span_len;
	bpf_map__set_max_entries(s->maps.page_state, pages);
#define RUP(x) (((x) + page - 1) & ~(size_t)(page - 1))
	size_t arena_bytes = RUP(span_len / 2) + RUP(span_len / 32) +
			     RUP(span_len / 64) + RUP(span_len / 128);
	bpf_map__set_max_entries(s->maps.fwd_arena, arena_bytes / page);
	if (gc_b0_ops_bpf__load(s)) { fprintf(stderr, "LOAD FAILED\n"); return 2; }
	{
		struct bpf_prog_info info = {};
		__u32 len = sizeof(info);
		int fd = bpf_program__fd(s->progs.handle_page_fault);
		if (!bpf_prog_get_info_by_fd(fd, &info, &len))
			printf("verified_insns=%u\n", info.verified_insns);
	}
	printf("LOAD OK\n");
	gc_b0_ops_bpf__destroy(s);
	return 0;
}

# SPDX-License-Identifier: GPL-2.0-only
#
# gc-bpf-fault microbenchmarks.
# Builds against the bpf-fault kernel tree's libbpf (which carries
# bpf_map__attach_fault_ops) and the running kernel's BTF.

KDIR     ?= /mydata/linux
BPFTOOL  ?= $(KDIR)/tools/bpf/bpftool/bpftool
LIBBPF_SRC = $(KDIR)/tools/lib/bpf
BUILD_DIR  = $(CURDIR)/build
LIBBPF_DIR = $(BUILD_DIR)/libbpf
INCLUDE_DIR = $(BUILD_DIR)/include

CLANG    ?= clang
CC       ?= gcc

BPF_CFLAGS  = -g -O2 -target bpf -D__TARGET_ARCH_x86
USER_CFLAGS = -g -O2 -Wall -I$(INCLUDE_DIR) -I$(CURDIR)
USER_LDFLAGS = $(LIBBPF_DIR)/libbpf.a -lelf -lz -lzstd -lpthread

VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

all: bench_wp_barrier bench_compact test_flip test_flip_unmap

$(LIBBPF_DIR)/libbpf.a: $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_DIR)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OUTPUT=$(LIBBPF_DIR)/ DESTDIR=$(BUILD_DIR) prefix= \
		all install_headers

$(LIBBPF_DIR):
	mkdir -p $@

vmlinux.h: $(BPFTOOL)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(BPFTOOL):
	$(MAKE) -C $(KDIR)/tools/bpf/bpftool

%.bpf.o: %.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	$(CLANG) $(BPF_CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

%.skel.h: %.bpf.o $(BPFTOOL)
	$(BPFTOOL) gen skeleton $< > $@

bench_wp_barrier: bench_wp_barrier.c gc_wp_ops.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

bench_compact: bench_compact.c gc_compact_ops.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

clean:
	rm -rf bench_wp_barrier bench_compact *.bpf.o *.skel.h vmlinux.h $(BUILD_DIR)

.PHONY: all clean

test_flip: test_flip.c gc_compact_ops.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

test_flip_unmap: test_flip_unmap.c gc_compact_ops.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

test_pmdmove: test_pmdmove.c gc_common.h
	$(CC) $(USER_CFLAGS) -o $@ $< -static

test_frag: test_frag.c gc_compact_ops.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

gc_kfixup_ops.bpf.o: gc_kfixup_ops.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	$(CLANG) $(BPF_CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

bench_kfixup: bench_kfixup.c gc_kfixup_ops.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

# Arena-based in-kernel fixup (needs clang>=19 for native addr_space_cast).
CLANG20 ?= clang-20
gc_kfixarena.bpf.o: gc_kfixarena.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	$(CLANG20) -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 -I$(INCLUDE_DIR) -I$(CURDIR) -c $< -o $@

bench_kfixarena: bench_kfixarena.c gc_kfixarena.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

gc_kompress.bpf.o: gc_kompress.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	$(CLANG20) -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 -I$(INCLUDE_DIR) -I$(CURDIR) -c $< -o $@

bench_kompress: bench_kompress.c gc_kompress.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

gc_kompress2.bpf.o: gc_kompress2.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	$(CLANG20) -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 -I$(INCLUDE_DIR) -I$(CURDIR) -c $< -o $@

bench_kompress2: bench_kompress2.c gc_kompress2.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

test_mremap_install: test_mremap_install.c gc_compact_ops.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

gc_satb_ops.bpf.o: gc_satb_ops.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	clang-20 $(BPF_CFLAGS) -mcpu=v3 -I$(INCLUDE_DIR) -I$(CURDIR) -c $< -o $@

test_satb: test_satb.c gc_satb_ops.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

gc_z_ops.bpf.o: gc_z_ops.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	clang-20 $(BPF_CFLAGS) -mcpu=v3 -I$(INCLUDE_DIR) -I$(CURDIR) -c $< -o $@

test_zheap: test_zheap.c gc_z_ops.skel.h gc_common.h $(LIBBPF_DIR)/libbpf.a
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

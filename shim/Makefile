# SPDX-License-Identifier: GPL-2.0-only
# libgcbpf.so — bpf_fault WP dirty-tracking shim for MMTk (dlopen'ed).

KDIR     ?= /mydata/linux
BPFTOOL  ?= $(KDIR)/tools/bpf/bpftool/bpftool
LIBBPF_SRC = $(KDIR)/tools/lib/bpf
BUILD_DIR  = $(CURDIR)/build
LIBBPF_DIR = $(BUILD_DIR)/libbpf
INCLUDE_DIR = $(BUILD_DIR)/include

CLANG    ?= clang
CC       ?= gcc

BPF_CFLAGS  = -g -O2 -target bpf -D__TARGET_ARCH_x86
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

all: libgcbpf.so

$(LIBBPF_DIR)/libbpf.a: $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_DIR)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 EXTRA_CFLAGS=-fPIC \
		OUTPUT=$(LIBBPF_DIR)/ DESTDIR=$(BUILD_DIR) prefix= \
		all install_headers

$(LIBBPF_DIR):
	mkdir -p $@

vmlinux.h: $(BPFTOOL)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(BPFTOOL):
	$(MAKE) -C $(KDIR)/tools/bpf/bpftool

gc_wp_ops.bpf.o: ../micro/gc_wp_ops.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	$(CLANG) $(BPF_CFLAGS) -I$(INCLUDE_DIR) -I$(CURDIR) -c $< -o $@

gc_b0_ops.bpf.o: gc_b0_ops.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	clang-20 $(BPF_CFLAGS) -mcpu=v3 -I$(INCLUDE_DIR) -I$(CURDIR) -c $< -o $@

gc_satb_ops.bpf.o: ../micro/gc_satb_ops.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	clang-20 $(BPF_CFLAGS) -mcpu=v3 -I$(INCLUDE_DIR) -I$(CURDIR) -c $< -o $@

%.skel.h: %.bpf.o $(BPFTOOL)
	$(BPFTOOL) gen skeleton $< > $@

libgcbpf.so: gcbpf.c gc_wp_ops.skel.h gc_b0_ops.skel.h gc_satb_ops.skel.h $(LIBBPF_DIR)/libbpf.a
	$(CC) -g -O2 -Wall -fPIC -shared -I$(INCLUDE_DIR) -o $@ $< \
		$(LIBBPF_DIR)/libbpf.a -lelf -lz -lzstd -lpthread

clean:
	rm -rf libgcbpf.so *.bpf.o *.skel.h vmlinux.h $(BUILD_DIR)

.PHONY: all clean

# gc-bpf-fault

`bpf_fault` support for the MMTk garbage collector: the eBPF fault handlers,
the loader shim that MMTk `dlopen`s, and the DaCapo benchmark driver.

This repository is a submodule of the [bpf-fault
artifact](https://github.com/bpf-fault/bpf-fault); the GC experiments are
driven from `eval/gc/` there. It is used together with the `gc-bpf-fault`
branches of [mmtk-core](https://github.com/bpf-fault/mmtk-core) and
[mmtk-openjdk](https://github.com/bpf-fault/mmtk-openjdk).

Two techniques are evaluated, both replacing a `userfaultfd` mechanism with
in-kernel fault handling:

- **Dirty tracking** for generational collection. After each nursery GC, clean
  mature-space pages are write-protected; the first write to a page faults and
  marks it dirty, and the dirty-page set becomes the remembered set for the
  next nursery collection. This replaces GenImmix's compiled write barrier.
  Baselines: `mprotect`+SIGSEGV, `userfaultfd` WP, and the barrier itself.
- **Concurrent compaction** for the Compressor. At the flip pause the heap's
  physical pages are moved aside into a from-space arena and the heap range is
  registered for missing faults; mutators resume immediately and a page is
  materialized on demand, in-kernel, when one touches it. Baselines:
  stop-the-world compaction and a `userfaultfd` `UFFDIO_COPY` integration.

## Layout

```
gc-bpf-fault
|-- shim/       : eBPF handlers and libgcbpf.so, the loader MMTk dlopen's
|   |-- gc_wp_ops.bpf.c : write-protect handler (dirty tracking)
|   |-- gc_b0_ops.bpf.c : missing-fault handler (concurrent compaction)
|   |-- gcbpf.c         : gcbpf_* C API called from mmtk-core
|   \-- loadcheck.c     : standalone verifier smoke test
\-- scripts/    : run_gc_bench.py, the DaCapo benchmark driver
```

## Build

Requires the bpf-fault kernel tree for the modified libbpf
(`bpf_map__attach_fault_ops`) and bpftool, a running bpf-fault kernel (the
BPF skeletons are generated from its BTF), and clang 20 or newer.

```sh
make -C shim              # KDIR defaults to ../../linux
```

`install_gc.sh` in the artifact runs this, along with the OpenJDK and MMTk
builds it depends on.

## Run

`scripts/run_gc_bench.py` runs one DaCapo benchmark under a set of MMTk
configurations and appends one JSON record per invocation, so an interrupted
run resumes where it stopped:

```sh
sudo ./scripts/run_gc_bench.py --klass B --bench h2 --heap 768M \
    --configs None,Uffd,R1 --invocations 3 --pauses -n 6
```

`--klass A` selects GenImmix dirty tracking (`Barrier`, `Segv`, `Uffd`, `Bpf`),
`--klass B` the Compressor (`None` for stop-the-world, `Uffd`, `R1` for the
in-kernel handler). `--pauses` adds a bpftrace-instrumented invocation that
measures every stop-the-world window. The JDK, DaCapo jar, and shim are taken
from `GC_JDK`, `GC_DACAPO`, and `MMTK_BPF_SHIM`, which `eval/gc/run.sh` sets.

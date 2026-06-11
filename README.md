# gc-bpf-fault

Garbage collection on top of `bpf_fault` (in-kernel eBPF page-fault handling),
with userfaultfd and mprotect+SIGSEGV baselines.

Two technique classes are evaluated:

- **Class A — page-protection write barrier for generational GC** (Cracauer-style):
  after each nursery GC, clean mature-space pages are write-protected; the first
  write to a page faults and marks it dirty. The dirty-page set is the remembered
  set for the next nursery collection. Replaces the compiled software write barrier.
- **Class B — concurrent compaction via missing faults** (ART CMC / Compressor-style):
  at the flip pause the heap's physical pages are moved aside (from-space) and the
  heap range becomes missing-fault-registered. Mutator accesses to uncompacted
  pages fault and the page is materialized on demand while a GC thread sweeps
  linearly.

## Layout

- `micro/` — mechanism microbenchmarks (no JVM):
  - `bench_wp_barrier` — Class A shape: repeated GC cycles of
    protect-all → multithreaded mutator writes → collect dirty set.
    Backends: `bpf` (bpf_fault WP, in-kernel dirty bitmap), `uffd`
    (uffd-WP + handler thread), `segv` (mprotect+SIGSEGV), `none` (floor).
  - `bench_compact` — Class B shape: to-space page materialization from a
    populated from-space. Backends: `bpf` (in-kernel copy in the missing-fault
    handler), `uffd_sigbus` (ART policy: UFFD_FEATURE_SIGBUS, mutator
    self-services with UFFDIO_COPY), `uffd_thread` (handler thread +
    UFFDIO_COPY), `segv` (PROT_NONE + mprotect/copy in handler; note: not
    multi-thread-atomic — readers can slip through between mprotect and copy,
    which is precisely why uffd/bpf_fault atomic install exists).
- `mmtk/` — notes and patches for the MMTk (mmtk-core/mmtk-openjdk) integration.
- `scripts/` — run/plot harnesses.

## Build

Requires the bpf-fault kernel tree (default `KDIR=/mydata/linux`) for the
modified libbpf (`bpf_map__attach_fault_ops`) and a running bpf-fault kernel.

```
make -C micro            # builds both benchmarks (sudo needed to run bpf backends)
```

## Run examples

```
sudo ./micro/bench_wp_barrier -t 8 -n 131072 -c 5 -f 0.25 -b all
sudo ./micro/bench_compact   -t 8 -n 131072 -b all -g
```

Each run emits greppable `RESULT ...` lines for plotting.

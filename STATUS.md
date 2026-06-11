# Status

## Done
- **Microbenchmarks** (`micro/`): `bench_wp_barrier` (Class A shape) and
  `bench_compact` (Class B shape), four backends each. Sweeps in `results/`.
  Headlines (131072 pages, 512 MiB):
  - WP fault p50 @16 threads: bpf 11.3µs / uffd 134µs / SIGSEGV 242µs; bpf
    scales with threads (mutate phase 96ms@1t → 24ms@16t), others anti-scale.
  - Compaction window @16 threads: bpf 53ms / uffd-SIGBUS (ART policy) 219ms /
    uffd-thread 443ms / SIGSEGV 954ms. Fault p50: bpf 2.8–6.2µs vs SIGBUS 6.6–34µs.
- **MMTk OpenJDK 21**: built at /mydata/openjdk-mmtk (fork @ b557520f04b,
  THIRD_PARTY_HEAP=/mydata/mmtk-openjdk/openjdk). Verified DaCapo
  (/mydata/dacapo/dacapo-23.11) lusearch on GenImmix.
  JDK: /mydata/openjdk-mmtk/build/linux-x86_64-server-release/images/jdk

## Class A: IMPLEMENTED (2026-06-11), validation in progress
All three backends pass DaCapo lusearch end-to-end with the compiled barrier
removed (verified: eBPF struct_ops live in the java process; non-root Bpf run
panics in shim load, proving the tracker initializes; option parse warns on
bogus values). Correctness sweep across 10 DaCapo benchmarks x 4 configs in
results/correctness/. Run with:
  sudo MMTK_PLAN=GenImmix MMTK_DIRTY_TRACKING={Barrier|Bpf|Uffd|Segv} \
    $JDK/bin/java -XX:+UseThirdPartyHeap ...
(JDK build needs MMTK_VO_BIT=1; Bpf backend needs root + shim/libgcbpf.so.)
Note: no RUST_LOG/info logging visible in the JVM (logger not initialized by
binding in this config) — use bpftool / behavioral checks instead.

Implementation (committed on gc-bpf-fault branches):
- mmtk-core: util/dirty_track.rs (tracker + 3 backends), dirty_tracking
  option, ScanVMDirtyPages packet (VO-bit page scan incl. spanning object),
  ScanDirtyStash packet, GenImmix prepare/end_of_gc protect/unprotect wiring,
  NoBarrier mutator gating. LOS/immortal/nonmoving conservatively re-scanned
  each nursery GC via stash enumerated in prepare BEFORE the LOS treadmill
  flips (enumerate_objects asserts outside-GC; tracing races otherwise).
- mmtk-openjdk: api.rs mmtk_active_barrier -> NoBarrier when tracking active.
- gc-bpf-fault/shim: libgcbpf.so (skeleton load/attach, multi-region
  register, WP enable/disable, mmaped dirty bitmap), dlopen'ed by mmtk-core.

## Class A remaining
- Sweep results -> fix any failures.
- Perf evaluation harness: multiple invocations, heap sizes 1.5-6x min heap,
  GC-time/mutator-time split (DaCapo callbacks or -Xlog:gc), all 4 configs;
  PGO builds for the paper-grade numbers (see mmtk-openjdk README).
- Known v1 simplifications: LOS not WP-tracked (conservative rescan instead;
  fine for most benchmarks, costly for LOS-heavy ones); per-cycle protect of
  ALL mature chunks (could protect only previously-dirty ones); VO_BIT=1 in
  all configs (same alloc cost everywhere, fair).

## Old design notes (Class A)
GenImmix + runtime option `vm_dirty_tracking=none|bpf|uffd|segv`:
- api.rs `mmtk_active_barrier()` returns NoBarrier when enabled (no compiled
  barrier in C1/C2/interp); mutator barrier semantics likewise.
- `GenImmix::release()` (STW, before mutators resume): write-protect all mature
  pages (chunk_map.all_chunks() for ImmixSpace + common plan spaces/LOS).
- Fault handlers record dirty pages (bpf: eBPF sets bit in mmapable array map;
  uffd: handler thread; segv: chained SIGSEGV handler + mprotect).
- `GenImmix::prepare()` (nursery): read+clear dirty set, scan dirty pages via
  VO bit (`MMTK_VO_BIT`; use find_object_from_internal_pointer for objects
  spanning page start), feed ProcessNodes<GenNurseryTrace> in Closure bucket
  (mirrors ProcessModBuf, gc_work.rs:77-121).
- bpf backend loads eBPF via a C shim lib (built in this repo against the
  kernel tree's libbpf), dlopen'ed by mmtk-core to avoid cargo/libbpf coupling.
- Newly mapped chunks must be registered with the bpf link (multi-region
  BPF_FAULT_REGISTER) before they can be WP'd — hook at Release time by
  re-walking chunk map (registration is idempotent per VMA? verify; else track).
- THP confound: bpf-fault/uffd VMAs disable THP → run *all* configs with
  transparent_hugepages=false.
- Recon notes (file:line map of mmtk-core/openjdk binding) in the session
  transcript; key spots: plan/generational/{mod.rs:40-55 GEN_CONSTRAINTS,
  gc_work.rs ProcessModBuf, immix/global.rs:125-154 prepare/release},
  util/object_enum.rs VO-bit scan, util/heap/chunk_map.rs all_chunks,
  openjdk/share/mmtkBarrierSet.cpp:82-92 + mmtk/src/api.rs:58-69 barrier select.

## Class B design (pending)
Concurrent Compressor in MMTk; v1 userspace compaction (GC thread stages pages,
eBPF missing handler installs by copying staged page; unprocessed-page faults →
handler returns error → SIGBUS → mutator runs ART-style compaction of that page
then retries; uffd baseline = SIGBUS + UFFDIO_COPY per ART).

## bpf-fault gaps observed so far
- None blocking yet. Candidates to highlight: (1) no userspace "install page"
  command (UFFDIO_COPY equivalent) — Class B v1 works around via
  fault-retry-after-staging; (2) WP-protect of large sparse range each GC may
  want chunked/async variant (cf. snapshot finalize fix).

## Repos
- /mydata/gc-bpf-fault (this repo), /mydata/mmtk-core, /mydata/mmtk-openjdk
  (both clean clones; our changes go on branch `gc-bpf-fault`),
  /mydata/openjdk-mmtk (JDK fork build tree), /mydata/dacapo.

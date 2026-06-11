# Session summary — 2026-06-11: GC on bpf-fault

Goal: use bpf-fault to improve garbage collection, per the Cracauer article
(page-protection write barriers) and the Google TD Commons disclosure (ART's
userfaultfd concurrent compaction). Decisions made this session: do both
technique classes; mprotect+SIGSEGV as a third baseline; Class B with
userspace compaction logic first, in-kernel fixup later; GenImmix first;
microbenchmarks live in this repo, not the kernel tree.

## What was accomplished

### Phase 0 — infrastructure (DONE)
- This repo (`/mydata/gc-bpf-fault`), with microbenchmarks, shim, scripts,
  results, docs. Kernel API examples live in
  `/mydata/linux/tools/testing/selftests/bpf/bench_fault/`.
- MMTk OpenJDK 21 built and running DaCapo: `/mydata/openjdk-mmtk`
  (mmtk/openjdk fork @ b557520f04b), bindings `/mydata/mmtk-openjdk` +
  `/mydata/mmtk-core` (pinned rev 37d81218, path dep, branch `gc-bpf-fault`
  in both). Build:
  `make CONF=linux-x86_64-server-release THIRD_PARTY_HEAP=/mydata/mmtk-openjdk/openjdk MMTK_VO_BIT=1 images`
  Run: `sudo MMTK_PLAN=GenImmix MMTK_DIRTY_TRACKING={Barrier|Bpf|Uffd|Segv}
  $JDK/bin/java -XX:+UseThirdPartyHeap ...` (Bpf needs root; shim at
  `shim/libgcbpf.so`, override path with MMTK_BPF_SHIM).
- DaCapo 23.11-MR2-Chopin at `/mydata/dacapo/dacapo-23.11`.

### Microbenchmarks (`micro/`, DONE — results in `results/*.log`)
- `bench_wp_barrier` (Class A shape): WP-fault dirty tracking p50/fault:
  bpf 2.9→11.3µs (1→16 threads, scales) vs uffd 16→134µs vs SIGSEGV
  9→242µs (anti-scale).
- `bench_compact` (Class B shape): materialize 512MiB: bpf 412→57ms
  (1→16t) vs uffd-SIGBUS (ART policy) 912→279ms vs uffd-thread/SIGSEGV
  worse. bpf ≈2.2–5x faster than ART's production policy.
- `test_flip`: ART's flip primitive validated on bpf-fault —
  mremap(MREMAP_DONTUNMAP) + register + in-kernel materialization from the
  alias. 1GiB: mremap 0.38ms + register 0.63ms (≈ the entire would-be
  pause), 2.6µs p50/page, contents verified. Class B's key de-risk.

### Class A — page-WP generational barrier in GenImmix (IMPLEMENTED)
mmtk-core changes (committed, branch `gc-bpf-fault`):
- `util/dirty_track.rs`: tracker + 3 backends (bpf via dlopen'ed shim;
  uffd-WP handler thread; chained SIGSEGV+mprotect), `dirty_tracking`
  option, page bitmap over the heap span.
- `ScanVMDirtyPages` packet (VO-bit scan of dirty pages incl. spanning
  object, 256MiB search bound), `ScanDirtyStash` packet.
- GenImmix wiring: unprotect-all + stash in `prepare` (before LOS treadmill
  flip), protect-all (immix chunks + coalesced LOS object page runs) in
  `end_of_gc`; NoBarrier mutator gating; binding's `mmtk_active_barrier`
  returns NoBarrier when active. JDK build needs MMTK_VO_BIT=1.
- Correctness: v1 sweep 40/40 PASS (10 DaCapo benchmarks x 4 configs).
  v2 sweep (after LOS fix) was 11/11 PASS when stopped — **REMAINING: finish
  v2 sweep + perf rerun**: just run
  `scripts/correctness_sweep.sh > results/correctness_sweep_v2.txt` and
  `scripts/perf_quick.sh results/perf_quick_v2 > results/perf_quick_v2.txt`.

Performance so far (-Xmx4G, single invocations, NOT paper-grade):
- Round 1 (`results/perf_quick.txt`): lusearch Bpf ≈ Barrier parity
  (2295 vs 2425ms), uffd +15%, segv +30%; pmd Bpf +15%; xalan/h2 all
  page-WP configs ~2x slower — bpftrace (USDT probes scan_vm_dirty_pages /
  stash_space_sizes) attributed it to the conservative rescan of ~97k live
  LOS objects per nursery GC, NOT the fault path.
- LOS fix (WP-track LOS pages; committed): xalan Barrier 2831ms vs
  **Bpf 1129ms / Uffd 1228ms / Segv 1208ms — 2.5x faster than the compiled
  barrier**. Cause: object-grain modbuf rescans whole large arrays on one
  store; page-grain rescans only dirty 4KB pages. h2 expected to improve
  too — re-measure.

### Class B — concurrent compaction (DESIGNED, foundation validated)
- `docs/class-b-design.md`: modify the existing Compressor plan (NOT a new
  plan — user OK'd either): its SecondRoots-before-Compact phase order is
  exactly the ART flip point, and stock STW Compressor is the
  apples-to-apples baseline. Phases: B.0 STW fault-materialization
  (per-region mremap + shadow staging + install via faults, still STW) →
  B.1 resume-after-SecondRoots concurrent window (GC sweep thread + mutator
  SIGBUS self-service slow path, uffd UFFDIO_COPY baseline = ART policy).
- Compressor recon details (forwarding metadata lifetime, region structure,
  allocation rules during the window) are in the design doc.

## bpf-fault gaps to highlight (paper material)
1. No userspace page-install command (UFFDIO_COPY equivalent): bpf Class B
   slow path needs SIGBUS bounce + second (cheap, in-kernel) fault after
   staging. A BPF_FAULT_INSTALL command or sleepable wait-for-staging kfunc
   would remove it.
2. Chunked/async WP ops over large sparse ranges (same mmap_write_lock
   lesson as the snapshot finalize fix).
3. Note: kernel has a sleepable `bpf_fault_writeprotect` kfunc already —
   possibly useful for in-handler re-protection policies.

## Next steps (in order)
1. Finish v2 correctness sweep + perf rerun (commands above, ~1h machine
   time); confirm h2 improvement; fix any failures.
2. Class A eval hardening: more invocations, heap sweep 1.5–6x per-benchmark
   min heap, GC/mutator time split, latency-sensitive DaCapo subset
   (metered percentiles), eventually PGO builds (mmtk-openjdk README).
   Optional: protect only previously-dirty chunks; array-slice scanning for
   huge dirty objects.
3. Class B.0 then B.1 per docs/class-b-design.md.
4. Later: in-kernel reference fixup (Class B v2), paper writeup (the
   bpf-fault paper has a commented-out GC subsection in applications.tex).

## State of the machine
- All benchmark runs stopped; no background tasks.
- Branches: mmtk-core + mmtk-openjdk on `gc-bpf-fault` (committed);
  this repo committed on master. JDK image is built with the LOS fix.
- Memory file `gc-bpf-fault-project` in Claude's auto-memory points here.

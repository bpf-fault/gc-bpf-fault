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

---

# Session 2 summary — 2026-06-12/13: Class B concurrent compaction (B.0+B.1) + Class A heap-sweep eval (started)

## Class B (concurrent compaction via missing faults) — COMPLETE
Vehicle: modified the Compressor plan (mmtk-core, branch gc-bpf-fault).
- **B.0** (STW fault-materialization): per-region mremap(MREMAP_DONTUNMAP)
  flip into a linear arena, slide-compact at alias addresses, stage+install
  (bpf: in-kernel arena copy on touch; uffd: UFFDIO_COPY). Validated
  (fop/pmd/luindex/avrora, both backends).
- **B.1** (concurrent window): resume mutators after SecondRoots; flip+preset
  cursors in the pause; StageSweep packets stage regions concurrently on GC
  workers; mutator faults on pending pages handled by SIGBUS.
  - **steal-mode** (the throughput fix): a faulting mutator stages its OWN
    region in the SIGBUS handler (ART-style), per-region CAS coordinates with
    GC sweepers. Lock-free, address-indexed, HotSpot scan_object tls-agnostic.
- **Config**: MMTK_PLAN=Compressor MMTK_COMPACT_FAULTS={Bpf|Uffd}
  MMTK_COMPACT_CONCURRENT=true MMTK_NO_REFERENCE_TYPES=true
  MMTK_NO_FINALIZER=true (b0test JDK conf). Requires no-ref-types/no-finalizer
  (pause-tail ref work dereferences unstaged pages).
- **RESULTS** (h2, compaction-heavy): -29% avg STW pause (512M: 254->180ms;
  768M: 356->254ms) for +10% throughput (768M -n4: 30.3->33.4s; wait-mode
  was +45%, steal-mode fixed it). bpf~uffd on pause (mark+flip dominated);
  bpf edge = fewer window faults + per-fault latency. Correctness 12/12
  DaCapo configs. Data in results/classB/.

## Key findings this session (paper material)
1. **Flip needs NO kernel change.** Earlier "63ms flip -> move_normal_pmd
   fix" was a misattribution. Real flip = ~1.4ms (mremap 1.3 + register
   0.13 for 540MB). The 63ms was mremap(MREMAP_FIXED) tearing down the prev
   cycle's arena synchronously — fixed by concurrent MADV_DONTNEED in
   finish_region. Proven via micro/test_pmdmove.c (DONTNEED'd dest flips at
   PMD speed; kernel frees empty PTE tables so pmd_none holds) + test_frag.c
   (bpf_fault registration does NOT fragment the VMA). move_normal_pmd's
   !pmd_none guard is core-mm but doesn't fire for us; uffd-wp PTE forcing
   already exempts VM_BPF_FAULT.
2. **Two arena-release crashes** (micro/test_flip_unmap.c repro, no JVM):
   (a) armed region + released arena = SIGBUS (handler reads freed arena);
   fixed by unregister-before-release. (b) munmap of arena slot UAF-crashes
   HotSpot DerivedPointerTable at resume; use MADV_DONTNEED not munmap.
3. **wait-mode busy-spin is pathological**: 79e9 spins (~237 CPU-sec);
   yield doesn't help (intrinsic stall, not CPU starvation) -> steal-mode.

## virtme-ng harness (no node reboot for kernel iteration)
Kernel rebuilt w/ 9p+virtiofs (CONFIG_NET_9P/9P_FS/VIRTIO_FS, BPF_FAULT
preserved); bzImage at /mydata/linux/arch/x86/boot/bzImage. scripts/vng_test.sh
"<cmd>" (boots in ~5s, shares /mydata, -m 8G). scripts/vng_crash_check.sh
confirms crash+fix inside the VM.

## Class A eval hardening — IN PROGRESS (NEXT TIME)
Paper-grade heap-sweep harness: scripts/classA_eval.sh (heap = multiples of
per-benchmark DaCapo min heap (GMD), 4 configs x invocations, throughput +
metered latency). Min heaps: lusearch 19 xalan 13 h2 681 pmd 191 avrora 5
luindex/sunflow 29 (MB).
PARTIAL run (80/144, stopped) in results/classA/sweep.txt. **KEY FINDING**:
strong HEAP-SIZE SENSITIVITY contradicting the earlier rosy -Xmx4G numbers.
At tight heaps (2-4x G1 min = ~1-2x GenImmix min, pathologically GC-heavy):
  lusearch 2x: Barrier 6.2s | Bpf 13s | Uffd 24s | Segv 33s  (Bpf ~2x SLOWER)
  xalan 2x:    Barrier 3.7s | Bpf 6.1s | Uffd 9.3s | Segv 15s
Earlier at -Xmx4G (~200x min, rare GC): xalan Bpf -58%, lusearch parity.
=> The page-WP barrier pays protect-all-mature + scan-dirty EVERY GC; at high
   GC frequency this dominates. Ordering Bpf<Uffd<Segv holds throughout.

## NEXT STEPS (priority order)
1. Verify it's a heap effect not regression: re-run lusearch -Xmx4G on b0test
   JDK, confirm earlier ~parity reproduces (rules out a B.1-era regression in
   GenImmix dirty-tracking, which should be untouched).
2. **HIGHEST-VALUE Class A optimization**: protect only PREVIOUSLY-DIRTY mature
   chunks each GC instead of ALL chunks (the known v1 simplification). Should
   slash the tight-heap penalty. Also: array-slice scanning for huge dirty
   objects; drop the conservative immortal/nonmoving rescan if measurable.
3. Re-run the heap sweep (consider sweeping 4-8x G1-min since GenImmix min
   ~2x G1-min; the 2x point is pathological). Add GC-time/mutator split
   (bpftrace gc_start..gc_end sum) and h2 (separate, slow).
4. Optionally: in-kernel fixup (Class B v2), paper writeup.

## State
- All committed: mmtk-core + mmtk-openjdk on branch gc-bpf-fault; gc-bpf-fault
  on master. b0test JDK is the current build (GenImmix dirty-tracking + all
  Compressor B.1/steal-mode). Main JDK (linux-x86_64-server-release) is older.
- No background tasks running; machine idle.

## Class A crossover RESOLVED (2026-06-13, session 2 cont.)
The heap-sweep eval is complete. Page-WP barrier is two-dimensional:
- xalan (array-heavy): +63% @2x -> +4% @128x -> -58% @4GB (WINS at large heap)
- lusearch (scattered): +106% @2x -> +6% @256x (only parity)
- h2: +77-82% @2-3x (stayed in losing regime)
Root cause of tight-heap loss = per-GC WP re-arming (~5us/bpf WP call x
thousands of GCs). Tried promotion-block incremental opt -> WORSE (syscall
overhead); reverted; chunk-granular is best. bpf-fault fix that would help:
batched/vectored WP command. bpf<uffd<segv throughout. Data:
results/classA/{crossover,extreme}.txt. The earlier xalan-4GB -58% REPRODUCES.
mmtk-core reverted to committed chunk-granular (clean). ALL THREE CLASSES
(A barrier, B.0/B.1 concurrent compaction + steal-mode) complete + committed.

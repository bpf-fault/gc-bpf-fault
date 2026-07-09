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

## Session 3 (2026-06-13): Class B v2 in-kernel forward + arena opt + R1 WIP

### Class B v2 in-kernel reference forwarding — DONE, optimized, validated
The eBPF missing-fault handler now forwards references IN-KERNEL during page
materialization (MMTK_COMPACT_DEFER_FORWARD). Optimization arc (clean
interleaved best-of-5, pmd 512M):
  transducer scan +66% -> forward table -1.4% -> table in BPF arena -14%
  -> bpf_loop 1024->16 -21% -> reference bitmap in arena -23% (== uffd-defer).
bpf-defer now MATCHES/slightly beats native userspace (uffd-defer), with the
in-kernel fault-resolution advantage (5-6x fewer userspace fault round-trips).
Key pieces: forward table + refbits in a clang-20 BPF arena (map_extra=1<<44,
mmap MAP_FIXED), read direct via arena ptrs; bug found: compressed-oops SHIFT=0
for <=4GiB heaps so the table is WORD-indexed (>>3) not shift-indexed.
Committed: mmtk-core fce6f49, mmtk-openjdk 15c0350, gc-bpf-fault (several).

### Latency — HONEST result: parity, not a bpf win on app metrics
measure_b2_latency.sh: lusearch showed bpf-defer ~43% lower MAX latency than
uffd, but h2 contradicted it (tied at all percentiles). So that was noise/
benchmark-specific. End-to-end (throughput + tail latency): bpf-defer == uffd-
defer. The robust difference is structural (bpf ~5-6x fewer fault round-trips;
micro per-fault ~3-6us in-kernel vs ~7-34us uffd SIGBUS) but faults are too
small a fraction of runtime to move app numbers. This motivated R1.

### R1: full in-kernel compaction (drop userspace staging) — WIP, ONE BUG LEFT
Goal: handler builds each to-space page from UN-SLID from-space, removing the
userspace slide-compact copy (work uffd cannot avoid -> where bpf would pull
AHEAD). Gated MMTK_COMPACT_INKERNEL; B v2 path UNAFFECTED (re-verified PASS).
- De-risk gc_kompress2 (commit 83b51b0): probe_read from-space chunk -> arena
  scratch + flat fwd table, ~16us/page (== arena-direct). Lessons: clamp read
  to resident region; flat table avoids 1M-insn verifier limit; per-cpu scratch.
- BUILT (commit gc-bpf-fault 5780b1b, mmtk-core 742f913c): arena =
  [fwdtable|refbits|livebits|first_src]; calculate_offset_vector emits live-word
  bitmap + per-page first_src; stage_region_idx R1 branch records ref bits at
  OLD positions + SKIPS copy/install (record_ref_bits_old); handler emit_compact
  builds page from from-space (per-cpu r1_scratch_map, region-clamped read,
  per-region stop, 4-byte compressed-oop forward).
- VALIDATED: compaction works (built pages decode to real compacted data, e.g.
  a char-array page = clean ASCII "(Ljava/lang/invoke/...").
- **BUG**: crashes early (guarantee: module is null). Telemetry (MMTK_R1_DEBUG):
  staged_installs=1, refs_fwd=38, fault_count=11. So only ONE page built across
  11 faults -> ~10 faults did NOT produce a built page. POINTS AT STAGING/
  page-state, NOT the forward: pages aren't becoming STAGED on the steal/retry
  path, or staged_end is too small so compacted pages read ZERO_FILL -> null
  ref. NEXT STEPS (next session):
  1. In R1 stage_region_idx, confirm cf.stage(start, staged_end-start) marks the
     right range, and that the steal path (handle_window_fault PENDING -> steal
     -> stage_region_idx -> retry) actually flips pages PENDING->STAGED in R1
     (B.0 install was skipped; verify the retry build path).
  2. Check whether stage_sweep (GC-worker staging of all regions) runs in R1, or
     only on-demand steal (only 1 region staged before crash?).
  3. Compare a built REFERENCE page (R1) vs the B v2 staged page at the same off
     (gcb0_dbg_print captures 8 words; gate both on a fixed off both reach).
  4. If staging is fine: the 38 forwarded refs in the one built page may include
     a wrong/missed one -> dump and diff vs B v2.
- Telemetry left in place (remove before final): gcb0_compact_words/prefail/
  dbg_print, dbg_w[8], MMTK_R1_DEBUG. r1_scratch_map per-cpu.

### State
- All committed. mmtk-core (742f913c) + mmtk-openjdk (15c0350) on branch
  gc-bpf-fault; gc-bpf-fault on master (5780b1b). b0test JDK is current build.
- R1 gated behind MMTK_COMPACT_INKERNEL (broken); B v2 (MMTK_COMPACT_DEFER_
  FORWARD) is the validated/optimized path. No background tasks; machine idle.
- Repro R1 bug: sudo env MMTK_R1_DEBUG=1 MMTK_PLAN=Compressor MMTK_COMPACT_FAULTS=Bpf
  MMTK_COMPACT_CONCURRENT=true MMTK_COMPACT_INKERNEL=1 MMTK_NO_REFERENCE_TYPES=true
  MMTK_NO_FINALIZER=true <b0test java> -XX:+UseThirdPartyHeap -Xms512m -Xmx512m
  -jar dacapo...jar luindex

## Session 4 (2026-07-06): machine reset recovery + R1 FIXED and validated

### Machine reset (node reimaged since 2026-06-13)
The node was reset: /mydata/openjdk-mmtk (JDK build) and /mydata/dacapo were
DELETED; mmtk-core/mmtk-openjdk were re-cloned and left parked on the
unrelated April branch experiment/bpf-fault-write-notify; the kernel tree
moved from /mydata/linux into the new /mydata/bpf-fault repo (as submodule
linux/).  Restored:
- mmtk-core + mmtk-openjdk checked out to gc-bpf-fault (742f913c / 15c0350).
- /mydata/linux is now a SYMLINK -> /mydata/bpf-fault/linux (keeps all
  Makefiles/scripts working; new tree has libbpf + bpftool built).
- openjdk-mmtk re-cloned (mmtk/openjdk @ b557520f04b), single conf `b0test`
  (--disable-warnings-as-errors, boot JDK apt openjdk-21). NOTE: the old
  linux-x86_64-server-release conf was not recreated; b0test is the only JDK.
- DaCapo 23.11-MR2-chopin re-downloaded to the same path.
- Installed on fresh node: clang-20 (BPF arena), rustup 1.92.0, zip/X11 dev
  libs, openjdk-21-jdk.  Shim + micro rebuilt and smoke-tested (bpf WP
  p50 2.8us @2t, matches history).  B v2 luindex re-validated PASS.

### R1 bug ROOT-CAUSED and FIXED (three defects, all committed)
Repro'd the session-3 crash exactly (staged_installs=1, refs_fwd=38,
fault_count=11, "guarantee: module is null").  It was NOT one bug but three:
1. **finish_region-before-install** (mmtk-core): R1 skipped cf.install()
   (lazy build intent) but stage_region_idx still ran cf.finish_region()
   immediately -> bpf unregister (faults on unbuilt pages bypass the handler:
   kernel zero-fill -> null refs) AND arena MADV_DONTNEED (from-space source
   destroyed).  Fix: install eagerly like B v2 -- the touch drives the
   in-kernel build, preserving R1's point (no userspace slide-copy).
2. **stale live bits** (mmtk-core): the R1 live-word bitmap was only OR'd;
   stale bits from the prior cycle emit dead words.  Fix: per-region clear in
   calculate_offset_vector (regions are 1MiB-aligned -> parallel-safe).
3. **single-chunk build + arena holes** (shim): emit_compact read ONE 8KiB
   chunk ("would reload" unimplemented) -> zero page tails.  And a naive
   reload -EFAULTs when a chunk crosses an arena HOLE (dead heap pages never
   materialized -> nothing mremap'd there); handler -14 -> SIGBUS -> retry ->
   infinite fault loop (75M retries, 2 GC workers spinning, observed).
   Fix: page-granular loads (holes are page-granular so reads are all-or-
   nothing per page), failed read = all-dead page, skip (any live word was
   mutator-written -> its page is mapped); also don't advance srcw past the
   scratch-overflow word.
Commits: mmtk-core b3ad57fc, gc-bpf-fault 93098b8.

### R1 VALIDATED (correctness) -- performance is the next arc
luindex/fop/pmd/avrora PASS @512M; h2 768M -n2 PASS (31.6M pages built
in-kernel, 10.57e9 refs forwarded in-kernel, prefail=hole-skips only).
B v2 regression: PASS (unchanged).
**Perf caveat**: h2 iteration ~188s vs stock ~30s (~6x).  Cause (analyzed,
not yet fixed): emit_compact is WORD-granular -- one bpf_loop iteration per
from-space word inspected (live or dead), so each region's live extent is
rescanned ~once per GC (~100M iterations/GC on h2).  Next optimization:
RUN-granular emit (walk the live bitmap word-at-a-time to find live runs,
copy runs in bulk), and/or skip-ahead via first_src of the next page.
luindex/fop/avrora show no visible regression (few GCs at 512M).

### State
- All committed: mmtk-core b3ad57fc + mmtk-openjdk 15c0350 (unchanged) on
  gc-bpf-fault; gc-bpf-fault master 93098b8.  b0test JDK current (only conf).
- No background tasks; machine idle.  Kernel 6.17.0-bpf-fault+ running.
- Next: R1 perf arc (run-granular emit), then the A/B/R1 comparison table
  (h2 pauses + throughput), then paper writeup.

## Session 4 (cont., 2026-07-06 evening): R1 perf arc + 6x B.1 regression found & fixed

### R1 emit optimization (task: "get performance better")
Word-granular emit_compact (1 bpf_loop dispatch + arena byte load per
from-space word, live or dead; ~50M dispatches/GC on h2) replaced by
64-word live-bitmap GROUP emit (gc-bpf-fault 37c7314 + fba6ef9):
- dead group = one u64 load; mixed group = inline bit-scan; fully-live
  group = direct-offset fast path (no popcount).
- **BPF verifier lesson (the hard part)**: a loop-carried accumulator
  (outw++) is path-precise verifier state — every live/dead branch forks
  states that never re-merge -> E2BIG at 1M insns. barrier_var does NOT
  help (compiler barrier only; the verifier still tracks values).  The fix
  is fwd_word's shape: NO loop-carried registers — output offset computed
  as a pure function outw0 + popcount(lw & bits_below(b)); page-boundary
  overflow group (≤1/fault) takes a per-bit bpf_loop slow path whose state
  lives in ctx MEMORY (havocked per callback, verified once).  Also moved
  the per-chunk loader into a bpf_loop so the branchy emit callsite is
  verified once, not 256x (open-coded outer loops re-walk callee bodies).
Effect: h2 -n2 iter 188s -> 138s; pmd 11.9 -> 9.0s.

### 6x B.1 regression: bisected to session 3, fixed (mmtk-core 0701dee5)
Baseline measurements exposed that B.1 (no-defer) h2 768M -n4 last-iter
was 202.7s vs session 2's 33.4s.  Bisect: bench_compact micro reproduces
June (kernel/env fine); a JDK built at session-2 mmtk state (mmtk-core
bbf01d40 + mmtk-openjdk 9fd0e8d, conf s2test) reproduces 33.4s EXACTLY ->
session 3's mmtk changes were the cause.  Root cause: fce6f495 made
stage_region_idx record the B v2 reference bitmap UNCONDITIONALLY —
set_ref_bit per reference slot (~42M/GC on h2) incl. a globally contended
telemetry atomic (REFBITS_POPULATED) — pure waste for B.1, which never
reads the bitmap.  Session 3 only compared B v2 variants to each other and
never re-ran B.1, so it went unnoticed.  Fix: record/clear ref bits only
when defer_forward(); count telemetry only under MMTK_REFBITS_DEBUG.

### Honest 4-config comparison (post-fix, h2 768M -n4 / pmd 512M -n4, last iter)
  h2:  stock 32.3s | B.1 35.7s (+10%) | Bv2 86.1s (+167%) | R1 92.5s (+186%)
  pmd: stock 2.77s | B.1 3.24s (+17%) | Bv2 4.54s (+64%)  | R1 4.89s (+77%)
Reading:
1. B.1 +10% reproduces session 2 — concurrent compaction's honest tax.
2. DEFER-FORWARD (fault-time forwarding) costs ~2.4x extra on ref-dense h2:
   the per-slot refbit recording at stage + random forward-table lookups at
   install are intrinsic to defer, not implementation slop.  This reframes
   B v2/R1: their price is the defer tax, in exchange for pages whose
   references are fixed up in-kernel at materialization (no userspace
   touch of the page at all — the R1 property the paper wants).
3. R1 (full in-kernel build) == B v2 within ~7-8% on both workloads: the
   in-kernel compaction copy adds ~nothing over the userspace-staged copy —
   the mechanism itself is sound and cheap; defer is the cost driver.
Data: results/classB/h2_n4_comparison_20260706.txt.
Correctness: B.1/Bv2/R1 luindex+fop PASS post-fix (plus earlier 5-benchmark
R1 sweep incl. h2).

### Known R1 caveat (document in paper)
record_ref_bits_old silently skips objects without slot-enqueuing support
(scan_object_and_trace_edges has no slot addresses).  Never triggered on
DaCapo/HotSpot, but it is a correctness hole if a VM has such objects in
the compressor space; B v2's staged path forwards those eagerly instead.

### State
- Committed: mmtk-core 0701dee5, gc-bpf-fault fba6ef9 (branches:
  gc-bpf-fault / master).  b0test JDK = current (all fixes); s2test JDK =
  session-2 bisect build (keep for reference or delete).
- Next: (a) defer-tax attribution (stage-time refbit recording vs
  install-time table lookups — bpftrace/perf), (b) R1 vs Bv2 pause
  comparison (measure_pauses.sh) — R1 should shorten the *stage* phase
  (no copy), (c) possibly batched WP / install-side prefetch as kernel
  items, (d) paper writeup.

## Session 4 (cont. 2): defer-tax decomposition + pause attribution (2026-07-06 night)

### Decomposition of the defer-forward tax (h2 768M; mmtk-core 49f91975)
Knob MMTK_FORCE_REFBITS (record refbits in non-defer mode, forward at stage
time) splits the tax:
- Stage-time refbit recording: **FREE** (B.1 35.7s == B.1+recording 35.7s
  -n4).  The pre-fix 6x regression was thus ENTIRELY the per-slot contended
  telemetry atomic, not the bitmap writes.
- STW set_fwd forward-table fill (CalculateOffsetVector packets, bpftrace
  uretprobe sums per -n1 run): B.1 6ms / Bv2 6.3s / R1 6.4s — real but
  minor (~30-40ms CPU per GC over parallel workers).  R1's livebits/
  first_src emission adds only ~50ms/run — negligible.
- **Install-time forwarding is the dominant tax**, and at h2's GC frequency
  it shows up as PAUSE time: half of all stops land while the previous
  window is still draining, and stop->window-close waits total
  B.1 31.3s | Bv2 78.8s | R1 84.7s (76 overlapped GCs, -n1).  The window
  has no slack, so work moved out of the pause queues the NEXT pause.

### Pause table (h2 768M -n2, ~271 GCs, whole process)
  stock: avg 377ms max 521ms | B.1: 269ms (-29%) max 558ms
  Bv2:   avg 604ms max 1458ms | R1: 641ms max 1520ms
B.1 reproduces session 2's -29% avg-pause headline.  Bv2/R1 pauses are
WORSE than stock STW — fully explained by window-drain queuing above.

### Paper-facing conclusions (Class B family, ref-dense/GC-frequent regime)
1. B.1 (staging-time forwarding): -29% avg pause for +10% throughput —
   the clean concurrent-compaction result; holds up.
2. Defer-forward (Bv2) and full in-kernel compaction (R1) both work
   correctly, and R1 == Bv2 (within ~8%): the in-kernel page build is
   free relative to userspace staging — the MECHANISM claim stands.
3. But fault-time reference forwarding is intrinsically expensive at
   scale (25-42M refs/GC): ~2.4x throughput and pause regression via
   window-drain queuing.  Defer modes need either (a) workloads with GC
   slack (bigger heaps / fewer refs), or (b) a way to cut install-time
   forward cost.  Candidate kernel/design items: batched install (fault
   N pages per handler entry), forward-table prefetch, or hybrid
   stage-forward for GC-staged regions + defer only for stolen regions
   (needs an idempotency marker — unsafe today).
Data: results/classB/h2_pause_defer_decomposition_20260706.txt.

### State
- Committed: mmtk-core 49f91975 (knob + prior fixes), gc-bpf-fault at
  fba6ef9 + docs commits; branches gc-bpf-fault / master; trees clean.
- bpftrace v0.20.2 installed from apt (works on 6.17.0-bpf-fault+;
  uprobes verified).  b0test JDK current; s2test = session-2 bisect build.
- Machine idle; no background tasks.

## Session 4 (cont. 3): Class B heap sweep + metered latency — the honest map (2026-07-06 late night)

Sweep (scripts/classB_sweep2.sh, data results/classB/sweep2/): h2 -n4 at
768M/1536M/3072M and xalan 1G, each under stock/B.1/Bv2/R1, capturing
DaCapo "simple" tail latency of the converged iteration.

### Results (h2: last-iter time / p99.9 tail)
  768M:  stock 32.4s/391ms | B.1 35.4s/418ms | Bv2 87.4s/1111ms | R1 92.6s/1188ms
  1536M: stock 10.2s/385ms | B.1 12.8s/423ms | Bv2 25.8s/1080ms | R1 26.9s/1146ms
  3072M: stock  6.2s/372ms | B.1  8.5s/403ms | Bv2 13.7s/1007ms | R1 13.7s/1118ms
  xalan 1G: stock 1173ms | B.1 1311 (+12%) | Bv2 1318 (+12%) | R1 1264 (+8%)
  xalan interleaved x3 (verification): R1 < B.1 in 3/3 pairs (~1-3%).

### Findings
1. **Tail latency is the metric that matters, and NO Class B variant beats
   stock's tail on h2 at any heap.**  The p99+ tail IS the worst GC pauses;
   stock's ~370-390ms p99.9 barely moves with heap size (same pause, rarer).
   B.1's -29% AVG pause never reaches the tail because the pause is
   mark-dominated and concurrent max pause is slightly WORSE (steal/window
   variance).  Cutting the tail requires concurrent MARKING — out of scope
   for the Compressor family.
2. **Slack hypothesis refuted on h2**: defer's ~1s tail persists at 3G.
   The window is sized by the (constant) live set, and h2's allocation
   rate re-triggers GC before the window drains at every tested heap.
   Defer/R1 lose 2.2-2.7x on time on h2 in ALL regimes.
3. **Ref density is the defer dimension** (analogous to Class A's write
   locality): on low-ref xalan the defer tax vanishes (Bv2 == B.1) and
   **R1 is the best fault-driven variant** — consistently 1-3% under B.1
   (3/3 interleaved) — the in-kernel page build is cheaper than the
   userspace slide-copy once forward work is small.  First regime where
   R1 strictly wins; also the bpf-only capability (uffd cannot build
   pages in-kernel).
4. B.1's honest position: +10-37% time, tail ~= stock (slightly worse).
   Its -29% avg pause is real but only helps pause-SENSITIVE metrics
   (e.g., allocation stalls), not request tails.

### Where this leaves the paper
- Class A: two-dimensional crossover (heap size x write locality) — DONE.
- Class B: two-dimensional too (ref density x GC frequency), but the
  tail-latency claim does NOT materialize for the Compressor family; the
  honest claims are (a) avg-pause reduction at bounded throughput cost
  (B.1), (b) the in-kernel-build capability at zero-to-negative cost in
  the low-ref regime (R1), (c) quantified kernel gaps (bulk-install:
  ~97s/run of fault round-trips on h2; batched WP for Class A).
- Next mechanisms if pursued: kernel bulk-install command (biggest lever,
  quantified), hybrid stage-forward+defer-on-steal (kills defer tax,
  keeps steal correctness), concurrent marking (out of scope).

### State
- Committed: gc-bpf-fault 7770570 + this docs commit; mmtk-core 49f91975.
  Machine idle, trees clean.  b0test current; s2test = bisect build.

## Session 4 (cont. 4): uffd columns + mremap-install micro (2026-07-06/07 midnight)

### uffd baseline columns (completes the ART-policy comparison; commit f94fd17)
  h2 768M: uffd-B.1 35.6s/421ms | uffd-defer 36.1s/442ms
  h2 3072M: uffd-B.1 8.2s/404ms | uffd-defer 8.3s/445ms
  xalan 1G: uffd-B.1 1290ms | uffd-defer 1346ms
Two conclusions:
1. **B.1 is mechanism-agnostic at app level** (bpf == uffd on time and tail
   everywhere).  The bpf-over-uffd claims live at the micro level (2.2-5x
   window, 3-6us vs 7-34us/fault, scaling) and in window-fault counts,
   NOT in end-to-end DaCapo numbers for the B.1 policy.
2. **The defer tax is OURS, not defer's**: uffd-defer pays ~nothing (it
   forwards the same refs at install time in USERSPACE, native loads),
   while bpf-defer pays 2.4x.  Root cause: the in-kernel install path's
   BPF-arena-heavy work (~16us/page vs ~3us plain copy, session-3 micro;
   x34M pages / 16 workers == the ~50s observed delta).  In-kernel
   forwarding via BPF arena loads is ~5x slower per page than userspace
   forwarding.  R1's xalan edge survives (R1 1264-1303ms beats uffd-defer
   1346ms and uffd-B.1 1290ms) -- in the low-ref regime the in-kernel
   build wins; in the ref-dense regime it loses to userspace forwarding.

### mremap-install VALIDATED (micro/test_mremap_install.c)
Install a staged region by mremap(MAYMOVE|FIXED) of the arena slot back
over the heap range -- the exact inverse of the flip -- instead of fault-
touching every page:
  install 43ms -> 0.02ms per 64MiB cycle (~2000x), zero faults, contents
  verified over repeated cycles, NO VMA fragmentation (vmas=1), works
  while armed (no unregister needed), next flip drops 6.8 -> 0.02ms
  (whole-VMA move path), arena slot becomes a hole on move-out (obsoletes
  finish_region's MADV_DONTNEED).
No kernel interface change.  JVM integration notes: per-region prefix
moves (staged_end-aligned), armed-remnant patchwork per region (micro
suggests merging behaves; verify at 1MiB granularity), steal-path does
its own region mremap from the SIGBUS handler.
=> NEXT: wire mremap-install into B.1 (+ userspace forwarding as today);
   expected: install phase ~360ms/GC -> ~10ms/GC, window drains long
   before the next GC, possibly recovering B.1's avg-pause win without
   tail damage, at near-stock throughput.

### State
- Committed: gc-bpf-fault f94fd17; trees clean; machine idle.

## Session 4 (cont. 5): mremap-install in the JVM — honest negative result (2026-07-07)

Wired MMTK_INSTALL_MREMAP into B.1 (mmtk-core 5d85e8dd, off by default):
stage keeps pages PENDING, one mremap moves the staged arena prefix over
the heap, state-clear releases SIGBUS waiters, arena slot re-mmap'd empty
(DerivedPointerTable safety).  Correctness: 6/6 PASS (Bpf+Uffd x
luindex/fop/pmd).

RESULT (h2 768M): touch 35.4s / 418ms tail / 269ms avg pause vs
mremap 38.5s / 444ms / 281ms — the 2000x micro win does NOT transfer:
+9% time, tail slightly worse, pauses equal.  WHY: B.1's install faults
were never the app bottleneck — 128k faults/GC parallelize across GC
workers on the mmap_READ_lock path, while mremap-install serializes
~1500 mmap_WRITE_lock VMA ops per GC against the allocation path's
zero-fill faults, and the per-region VMA patchwork makes the STW flip
slower.  (The drain-queued pauses belonged to the DEFER modes, where
mremap-install cannot apply — un-forwarded refs in the arena.)

PAPER INSIGHT (design space): page-install mechanisms that ride the
fault/read-lock path (touch-faults, UFFDIO_COPY) beat VMA-level
write-lock moves under GC-worker parallelism.  A future bpf-fault
bulk-install command should be a read-lock-path range operation (like a
vectored UFFDIO_COPY), NOT a VMA op — the mremap experiment is the
evidence.

### State: all committed (mmtk-core 5d85e8dd), trees clean, machine idle.

## Session 4 (cont. 6): uffd-defer anomaly resolved — attribution sharpened (2026-07-07)

The "uffd-defer is nearly free" result looked too good (25M refs/GC
forwarded at install for +1ms/GC?).  Probed install_page_uffd/forward_buf
(uprobes, h2 -n1): install_pages == fwdbuf calls == 19.3M (~130k/GC, defer
fully active), install+forward CPU = 40.2s over the run = **~2.1us/page
INCLUDING the UFFDIO_COPY**.  It is not free — it is parallel: /16 GC
workers ≈ 17ms wall/GC, well inside the inter-GC gap, so it vanishes
end-to-end.
The bpf handler pays ~16us/page for the same job (fault entry + arena-
heavy fwd_word) = ~2.1s CPU/GC, which SATURATES the window -> drain-
queued pauses -> the 2.4x.  CONCLUSION (confirmed + quantified): the
defer tax is the 7-8x per-page gap between our in-kernel install path
and userspace install; there is a THRESHOLD effect — getting bpf's
per-page cost under the window capacity would eliminate most of the
2.4x, not just shave it.
Candidate (no kernel interface change): replace the cache-hostile flat
forward table (384MB, ~1 miss/ref) with an in-kernel TRANSDUCER over
arena-resident offset vector (3MB) + mark bitmap (12MB) — cache-resident
working set, using the group/popcount verifier techniques from the
emit-group work (session 3's transducer attempt predates them).

## Session 4 (cont. 7): THE DEFER TAX WAS ATOMIC CONTENTION — bpf now beats stock AND uffd (2026-07-07)

Arc: transducer forward built (ov2 + live-bit popcount, bit-exact vs flat,
0 mismatches) -> no speedup -> exposed a latent bug (fwd_word had its own
inline flat-table read; skipping the fill under transducer mode left refs
stale -> deterministic h2 corruption; fixed: fwd_word -> forward_narrow)
-> bpftool prog profile gave the real answer:

**bv2 handler: 430,900 cycles/fault at IPC 0.07** (vs B.1's plain-copy
3,234 at 0.47).  The handler was ~entirely stalled on a CONTENDED GLOBAL
ATOMIC — __sync_fetch_and_add(&b0_refs_forwarded) per forwarded reference,
~150/page across 16 workers.  Third generation of the same bug class
(session 3: REFBITS_POPULATED userspace atomic; tonight: the in-handler
one).  The flat table's cache misses and BPF arena access costs were
red herrings; the transducer was unnecessary for speed (kept: it lets the
GC skip the 6.3s/run STW table fill).

### RESULT (atomics gated behind MMTK_R1_DEBUG): h2 768M -n4 last-iter / p99.9
  stock STW:   32.4s / 372ms      bpf B.1:   35.4s / 418ms
  uffd B.1:    35.6s / 421ms      uffd defer: 36.1s / 442ms
  **bpf Bv2:   28.7s / 336ms      bpf R1:    28.7s / 338ms**
bpf defer modes now beat STOCK (-11% time, -10% tail) and UFFD (-20% time,
-24% tail) on BOTH metrics.  Staging without forwarding shrinks the window;
in-kernel install forwarding is nearly free; the window drains before the
next GC; the concurrent-compaction pause win finally reaches the TAIL.
This is the paper's headline Class B result, and it is bpf-ONLY: uffd-defer
still pays userspace per-page forward (36.1s), and uffd cannot do R1 at all.
xalan 1G -n4: stock 1173 | b1 1291 | bv2 1272 | r1 1281 (defer best of the
fault variants there too).
Correctness: 12/12 (bv2/r1/bv2+transducer x luindex/fop/pmd/avrora) + h2 +
xalan PASS.  Commits: gc-bpf-fault d961c93, mmtk-core 716b62f1.

### Revised attribution chain (for the paper's honesty section)
1. defer tax != defer concept (uffd-defer cheap)         [cont. 6]
2. defer tax != per-page in-kernel work per se           [wrong at cont. 6]
3. defer tax == per-ref contended global atomic in the handler [PROVEN:
   430k cycles/fault -> 3-4k after gating; 3x total-time collapse]
Lesson recorded: on per-item hot paths (refs, words, slots), check shared-
cacheline atomics FIRST — this bug class has now cost us 3 rounds.

### Still open / next
- Re-profile handler cycles post-fix for the record; heap sweep + pause
  probe for the new bv2/r1; uffd columns at other heaps unchanged.
- Multi-invocation rigor for the headline table; then paper writeup.

### Post-fix handler profile (for the record, bv2 h2)
430,900 cycles/fault @ IPC 0.07 -> **42,988 @ IPC 0.68** (10x/fault; 3.4x
handler throughput).  Remaining ~29k insns/page = fwd_word scanning all
1024 slots via 16 groups (ctz-iteration over set bits is the known next
trim, ~2x, not yet needed for the headline).

## Session 4 FINAL: paper-grade rigor suite (2026-07-07 03:30)

### h2 768M -n4, MEDIAN OF 5 INTERLEAVED INVOCATIONS (time / p99.9 tail)
  stock STW:   33.31s / 404ms   [32.9..34.9]
  bpf  B.1:    36.23s / 435ms
  uffd B.1:    36.58s / 433ms
  uffd defer:  36.12s / 435ms
  **bpf Bv2:   28.63s / 334ms   [28.5..28.8]  (-14% time, -17% tail vs stock;
                                               -21% / -23% vs uffd-defer)**
  **bpf R1:    28.88s / 337ms**
STW pauses (uprobe, h2 768M -n2): stock 377/521ms avg/max | B.1 269/558 |
  **Bv2 231/451 | R1 236/451** — best avg AND best max.
Heap sweep (fixed defer): 1536M Bv2 11.0s/329ms (stock 10.2/385: +8% time,
  -15% tail) | 3072M Bv2 7.7s/332ms (stock 6.2/372: +25% time, -11% tail).
  At 768M defer wins BOTH metrics; at larger heaps it trades some
  throughput for consistent tail wins — the classic concurrent-GC
  tradeoff, now actually delivered.

### The Class B paper story, final form
1. Fault-driven concurrent compaction with DEFERRED in-kernel forwarding
   (bpf_fault) beats the STW baseline on throughput (-14%), request tail
   (-17%), avg pause (-39%) and max pause (-13%) on compaction-heavy h2 —
   and beats the production userfaultfd policy by -21%/-23%.
2. The capability is bpf-ONLY: uffd cannot forward in-kernel (uffd-defer
   pays userspace per-page forwarding: 36.1s) and cannot build pages
   in-kernel at all (R1).
3. Supersedes sweep2's interim "no variant beats stock tail" conclusion —
   that was measured with the handler atomics bug.
4. The mechanism ordering (bpf < uffd) now shows END-TO-END, not just in
   micro benchmarks.
Data: results/classB/rigor/.  All correctness green (12/12 + h2 + xalan).

## Session 5 (2026-07-07 morning): Class A dirty-chunk re-arming + counter gating

### Counter gating (4th atomic-bug-class instance; gc-bpf-fault 9a0e0bc)
Class A WP handler counted every fault on a contended global; Class B
handler still had 2/fault.  Gated: **Class B bv2 h2 -n4: 28.6 -> 26.2s
(now -21% vs stock)**; Class A lusearch@38M 13.1 -> 11.9s.

### Dirty-chunk re-arming (mmtk-core e989ca8a) — the Class A story rewritten
Nursery GCs keep mature protection ACROSS GCs; only chunks that lost it
(dirty pages, promotion blocks via a copy-allocator acquire hook) are
re-armed.  O(dirty) per GC instead of O(mature).  Full-heap GCs
fall back to the full walk.  Lock-free bitmaps throughout.
  h2@4G:  Barrier 3.79s vs Bpf 4.11s — **+54% -> +8.4%** (near-parity on
          the former worst case)
  xalan:  @1664M **-15%** (crossover moved below 128x; was +4% there),
          @26M pathological heap 8.0 -> 5.3s (-34%)
  lusearch: unchanged — scattered writes ARE the page-granularity
          boundary (documented, not hidden)
Correctness 12/12 across all three backends + full-heap transitions.

### Class A claims, updated
1. vs uffd/segv: bpf strictly dominates everywhere (unchanged).
2. vs compiled barrier: wins for write-clustered workloads from ~128x
   min-heap down to BELOW 8x after dirty-chunk re-arming; near-parity
   (+8%) on dense-write h2 at large heap; scattered-write lusearch
   remains the honest loss regime.
3. Two userspace-policy lessons for the paper: (a) re-arm cost must be
   O(write working set), not O(mature); (b) the atomic-contention bug
   class (4 instances now) — audit per-item hot paths first.

## Session 5 (cont.): ctz trim + Class A rigor — final tables (2026-07-07)

### ctz fwd_word (gc-bpf-fault 7574d27)
Handler 42,988 -> 26,553 cycles/fault @ IPC 1.02 (full session arc:
430,900 -> 26,553, 16x).  End-to-end h2 unchanged (handler off the
critical path post-atomics) — banked as window-CPU headroom.

### Class A rigor — median of 3 interleaved -n4 invocations
                      Barrier          Bpf                Uffd
  xalan@1664M:        1557ms           1290ms (-17%)      1274ms
  xalan@416M:         1198ms           1672ms (+40%)      —
  h2@4G:              3718ms/18.1ms    4013ms (+7.9%)/48ms  4765ms (+28%)/84ms
  lusearch@1216M:     1891ms/2.7ms     3288ms (+74%)/35ms   —
  (p99.9 "simple" tail after the slash where metered)

### Class A final claims
1. bpf <= uffd EVERYWHERE; decisive where faults are frequent (h2@4G:
   +7.9% vs +28%; tail 48 vs 84ms).  At points where dirty-chunk
   re-arming makes WP work rare (xalan@1664M), the mechanisms converge —
   itself a finding: the policy fix shrinks the mechanism gap.
2. vs the compiled barrier: WINS write-clustered workloads at >=128x
   min-heap (-17%), near-parity on dense-write h2 throughput (+7.9%),
   loses scattered-write lusearch (+74%) — page granularity physics.
3. HONEST latency caveat: the dirty-page scan lives in the nursery
   pause, so p99.9 grows (h2: 18 -> 48ms) even at time near-parity.
   Mitigation = concurrent/incremental dirty scanning — future work
   (Class B's window machinery is the obvious donor).
Data: results/classA/rigor/.  ctz correctness 4/4; Class A suite green.

## Session 5 (cont.): ideas 4 and 6 — SATB parked with analysis; compression validated (2026-07-07)

### Idea 4 (page-COW SATB concurrent marking)
- **M1 mechanism VALIDATED** (micro/test_satb): in-kernel pre-write page
  snapshots at WP-fault time, p50 8.9us incl. 2 page copies, 3.5GB/s,
  bit-exact mark-start content.  Two arena lessons: kernel stores to
  unpopulated arena pages are DROPPED (pre-touch mandatory); no arena
  atomics (byte flags instead).  The primitive is bpf-only (uffd-WP =
  30-50us round-trip per snapshot).
- **M2 integration PARKED as WIP** (ConcurrentImmix, MMTK_SATB_PAGES,
  off by default; luindex/pmd pass, xalan/lusearch fail).  Five bugs
  fixed en route (drainer livelock; unmapped-metadata ACCERR; concurrent
  candidate tracing vs in-flight allocation -> deferred trace; freed-
  chunk stale VO bits; drainer/FinalMark cursor race -> handshake).
  ROOT CAUSE that remains: conservative candidates can resurrect
  INTACT-DEAD objects whose children point into reused memory —
  conservative identification feeding an EXACT tracer is unsound.
  Sound design requires the allocation frontier at LINE granularity
  (per-line young filter); estimated as the single remaining piece.
  docs/satb-pages-design.md has the full analysis.  This is itself a
  contribution: it precisely characterizes what VM-based SATB needs
  from an exact VM.

### Idea 6 (compressed cold heap) — mechanism VALIDATED (gc-bpf-fault 1cfe08d)
In-kernel page decompression at missing-fault time (gc_z_ops +
test_zheap): 65536/65536 bit-exact decodes, **p50 4.97us per
decode-fault (~2us over a plain fault)**, ratio 1.4x/2.4x/4.6x at
30/60/80% zero words.  Codec is verifier-safe by construction (per-group
prefix + popcount indexing = pure-function offsets, the emit_group
lesson reapplied).  Adds a memory-footprint axis to the paper: cold
regions at ~2.4x compression with first-touch decode ~8x cheaper than
the uffd equivalent.  GC integration (cold-region selection, packed-
store management) = future work; the mechanism claim stands alone.

### State
All committed: mmtk-core 06c0b68e (SATB WIP off-by-default), binding
a3bb9ef, gc-bpf-fault 1cfe08d + docs.  All previously-green paths
(Class A, B.1, Bv2, R1) unaffected (SATB is env-gated).  Machine idle.

## Session 5 (cont. 2): M2 endgame — root cause found, kernel exonerated (2026-07-07)

User directive: "Don't park M2. keep going."  Outcome: the exact drain
design is DONE and oracle-verified; the residual crashes are NOT ours.

### The exact drain (replaces conservative scanning entirely)
VO-bitmap snapshot at InitialMark = mark-start allocation map AND
liveness-at-last-GC certificate (membership => object + children memory
intact).  FinalMark walks snapshot-map object starts overlapping each
flagged page (+ spanning head via 64MB reverse search), iterates fields
via live layout, reads slot VALUES from snapshots where pages were
written.  Zero conservative candidates => exact marking never marks
non-objects => no VO poisoning (the CopyFromMarkBits feedback loop that
sank the conservative design).  Differential oracle (MMTK_SATB_VERIFY,
compiled barrier on + page path classifying): extracted=2505 garbage=0
unmarked=387.  Extractor: verified clean.

### The corruption hunt (13 fix iterations -> systematic bisect)
Fix chain en route: drainer livelock; unmapped-metadata reads (x2);
deferred trace; freed-chunk VO; cursor handshake; validating closure;
VO self-poisoning -> conservative->exact pivot; LOS to_space-only and
alloc-nursery arming gaps; treadmill assert ordering; stale alloc-map
slices; 64MB spanning head; unbounded in_alloc_map read (5.5GB OOB).

Bisect (all verify-mode: page machinery passive):
  baseline 6/6 PASS; attach-only 3/3 PASS; register-only 3/3 PASS;
  bpf WP armed 0/6 (even with a NO-OP handler);
  MAINLINE uffd WP-async armed 0/3  <-- kernel path exonerated.
Micros (all PASS): 16T same-page atomic + plain-store races w/ re-arm,
DONTNEED interleave, read(2) copy_to_user into armed pages, WP_ENABLE
coverage 4096/4096, THP/mTHP disabled.  Kernel audit of register/
change_protection/resolution/install: mainline-equivalent.

### CONCLUSION
Write-protect fault latency on first page writes (~10us vs ~1ns)
exposes a latent race in upstream ConcurrentImmix (experimental).  It
reproduces with the COMPILED barrier doing all SATB work and mainline
uffd doing the arming: nothing of ours in the loop.  Paper angle: VM-
based barriers (bpf and uffd alike) exercise concurrent-GC
interleavings compiled barriers never hit; plan robustness under fault
timing is a real requirement.  Class A (GenImmix) and Class B
(Compressor) correctness are unaffected (STW plans; extensive sweeps).

### M2 status: design complete + verified; blocked on upstream plan race.
Options: chase the ConcurrentImmix race upstream; or A/B the barrier on
a hardened plan; or proceed with idea 6 integration + paper.

### Sensitivity probe (2026-07-07): frac=1/16 armed chunks -> still 2/2 FAIL
A handful of delayed stores suffices; the upstream race is a narrow
ordering window, not a progress-balance effect.  Draft upstream report:
docs/concurrentimmix-race-report.md.

### NEXT ARC: idea 6 GC integration (stable plans, unaffected by the race)
GenImmix + Class A dirty tracking supplies cold-page identification for
free: pages that stay CLEAN (WP-armed, never faulted) for K consecutive
GCs are cold -> compress to arena (userspace, 215ms/256MB), DONTNEED
originals, register gc_z_ops missing-fault decompressor.  Access
transparently decompresses in-kernel (p50 4.97us) -- GC tracing
included.  Metric: RSS/PSS timeline + benchmark time, stock vs
cold-compress, h2 at large heap.

## Session 5 (cont. 3): idea 6 integration COMPLETE (2026-07-07)

Compressed cold heap live on GenImmix (MMTK_ZHEAP=K): soft-dirty cold
detection (coexists with the missing-fault link where a WP link cannot),
K-clean-GC threshold, ratio-gated userspace compression + MADV_DONTNEED
at end_of_gc, in-kernel decompression on first access (gc_z_ops).

### Final numbers (ColdCache: 1GB 75%-zero cold LOS data + 64MB hot
### loop, 90s, 3GB heap, K=2 sweep-every-4):
  stock  steadyRSS=3648MB  ops=1317M
  zheap  steadyRSS=3338MB  ops=1298M
  => -310MB RSS (-8.5%) at -1.5% throughput; 42 decode faults total;
     1.09GB cold compressed to 284MB (3.92x on selected pages).
Correctness: luindex/xalan/pmd PASS under MMTK_ZHEAP; cold-data
checksum identical stock-vs-zheap end-to-end through real GCs.

### Honest boundaries + integration findings (each measured):
1. DaCapo has no durably-cold heap: compression churns and the arena
   ADDS residency (h2: ratio 1.02x, +365MB RSS, 3x slower iter before
   selectivity).  Negative result documented like mremap-install.
2. LOS invisibility: 64KB+ arrays (the classic cold cache) live in the
   LOS; sweeping only mature immix chunks missed the whole cold set.
3. Ratio selectivity (MMTK_ZHEAP_MAXSZ, default commit-if<=2048B):
   dense pages are not worth arena residency.
4. Header-deref thrash: get_current_size in the sweep's own LOS
   enumeration faulted back one page per cold object per GC (measured
   16,394-page compress/decompress oscillation, 443k faults) ->
   immutable-extent cache; faults 196,776 -> 165.
5. clear_refs cost: soft-dirty reset write-protects every PTE ->
   hot-set refaults each sweep (~20% throughput) -> sweep every 4th GC
   (MMTK_ZHEAP_EVERY) -> -1.5%.
6. Full-GC retrace faults the compressed set back by design (tracing
   reads objects); rare in production generational configs; a future
   mark-on-compressed-image path could avoid materialization.

The paper's memory-footprint axis is now real: uffd could only match
this with a 30-50us round-trip + userspace decode per first touch
(~8x our 4.97us in-kernel decode), and no compiled-code alternative
exists.

## Session 5 (cont. 4): "fix the ConcurrentImmix race" — resolved by re-attribution (2026-07-07)

Phase-controlled bisect (pulse/initial/final arm phases + sleep-only +
comm-capture + scheduler event tracing) followed by a DRAIN-SILENCED
matrix produced the grand re-attribution — see mmtk-core ec64c307 and
the rewritten docs/concurrentimmix-race-report.md:
  * kernel bpf-fault WP: exonerated (passive arming 7/7 with compiled
    barrier once our drain was out of the signal);
  * mainline uffd: never implicated (our EBUSY harness asserts);
  * ConcurrentImmix: one REAL structural defect found + fixed as
    hardening (FinalMark loses Concurrent-bucket SATB packets:
    stop-time flushes + trace children mis-routed; pause never drains
    the bucket; packets execute post-pause with marking off) — verified
    by event trace (32 packets rerouted), though not the firing bug in
    our workloads;
  * the firing bug was OUR M2 drain: lazy-sweep hole in the liveness
    certificate (fixed: snapshot AND current-VO filter — mark-start-live
    objects cannot be lazily swept mid-cycle) + unbounded accessors
    (bounds-hardened) + one REMAINING extraction-stage deref in cycle 2+
    (stage markers localize it: between "flagged" and "extracted" of the
    second GC cycle; real mode still red, first cycle drains clean:
    32 pages -> 4916 nodes -> wholesale 13).

Verify-mode page-SATB (passive arming + compiled barrier) is now GREEN
4/4 on the previously 0/6 config.  NEXT: the cycle-2 extraction deref,
then real-mode suite, then compiled-vs-page A/B.

## Session 5 (cont. 5): real-mode page-SATB convergence (2026-07-07 evening)

After the race re-attribution, real-mode M2 greening proceeded through
six more characterized fixes (mmtk-core 33ce67d + follow-ups):
  14. current-VO liveness filter (lazy-sweep certificate hole);
  15. bounds-hardened satb accessors (wild slot addresses from
      corrupted-object iteration are expected inputs, not invariants);
  16. LOS rescue restored (wholesale rescan covers only to_space, so
      refs into LOS from overwritten immix slots must be traced from
      snapshots -- dropping them caused BootstrapMethodError-class
      under-retention);
  17. 8-byte alignment filter (snapshot data aliasing the alloc-map's
      8-byte bit granularity produced ObjectReference 0x...0001, traced
      into the LOS treadmill, crashing later enumeration -- register
      autopsy RSI=0x4c0d0001);
  18. untraced handoff (pre-tracing rescued refs marked-without-scanning
      => children never traced => under-retention);
  19. validating closure v2 + wholesale liveness split: intact-dead
      extraction sources/seeds have STALE slot values, so children must
      be validated per hop; live-certain seeds (immortal-by-definition,
      LOS to_space=traced-this-cycle) scan parallel+unvalidated.

MILESTONES: luindex PASSED real page-SATB mode end-to-end (first ever);
pmd PASSED real mode on the liveness-split build.  Remaining failures
shuffle between benchmarks per build = residual RACE-dependent bugs;
single-run-per-build attribution is no longer valid (flakiness gauge
running).  Known remaining levers, next session:
  - multi-run protocol per build before attributing:
  - weak-ref load gap (page mode cannot see Reference.get(); noref
    config or hybrid weak-ref-only compiled barrier via the binding's
    set_weak_ref_barrier_enabled gate);
  - EAGER sweeping probe: disabling lazy sweep eliminates the entire
    intact-dead class (the root of fixes 14/19) -- likely the single
    highest-value structural simplification for page-mode SATB.

### Flakiness gauge (liveness-split build): luindex 2/3, pmd 2/2.
The current build is PARTIALLY GREEN with a residual race (not
deterministic failure): the multi-run protocol is now mandatory for
attribution.  Prior single-run "regressions" (e.g. luindex on the
unified-closure build) were likely race noise, not causal.

## Session 5 (cont. 6): real-mode convergence, closing scoreboard (2026-07-07 night)

Fixes 20-23 (mmtk-core, committed): in-span slot gates in BOTH
iterators (extraction + validating closure) -- garbage oop-maps yield
wild slot addresses and iterate_fields faults internally reading the
oop map, so gates protect the s.load()s while the OBJECT-level bogosity
remains; non-moving pin for page mode (defrag evacuation vs drain
address iteration); boundary-head guard (BOTH observed deterministic
crashes were vo=true am=true "objects" at exactly pstart-8 with garbage
klass; genuine 16-byte objects there are header-only with no ref
fields, so skipping is lossless in the common case).

SCOREBOARD (x2 each): luindex 2/2, xalan 1/2 (FIRST real-mode xalan
pass), lusearch 0/2, pmd 0/2.  ~23 characterized bugs total.

OPEN LEADS for next session (entry point):
1. Bogus boundary-VO root cause: what sets vo(+alloc-map) bits at
   page_end-8 positions that hold garbage klass words at drain time?
   (Suspects: lazy line-recycle VO hygiene; VO-vs-mark CopyFromMarkBits
   timing for blocks never re-touched by the allocator; filler objects.)
2. Klass-range validation upcall from the binding (compressed class
   space bounds) = airtight object-validity predicate, replaces the
   heuristic guards; ~20 lines in mmtk-openjdk + one Rust hook.
3. Residual race on lusearch/pmd (mode unknown -- gather crash-vs-
   validation stats first with the multi-run protocol).
4. Weak-ref exonerated for xalan/lusearch (noref made no difference).

## Session 5 (cont. 7): design synthesis + gap isolation (2026-07-07 late)

Design converged to the SYNTHESIS (mmtk-core 1db3650, binding 4a37ddd):
conservative dword extraction of snapshot pages (NO object-layout walks
-- every crash class traced to iterating possibly-bogus objects) + a
per-hop validated closure with an exact validity oracle (aligned;
alloc-map/space; current VO; klass window over the self-refreshing
committed class-space segments; KlassKind tag via binding upcall).

SCOREBOARD (x3 each): luindex 3/3 (deterministic green), pmd 1/3,
xalan/lusearch 0/3 (deterministic Java-level under-retention).

SYSTEMATICALLY DISCONFIRMED for the residual gap (each tested):
  - weak/soft references (noref: no change)
  - defrag evacuation (non-moving pin: no change for these)
  - closure over-filtering (counters: ~0 rejects on ~100k traced/pause)
  - non-heap slot mutation (FinalMark full root RESCAN: no change;
    reverted)
  - klass-oracle over/under (single-segment vs multi-segment vs +tag
    A/B'd; tag restored luindex determinism)

REMAINING SUSPECTS (next-session entry, in order):
  1. SILENT SNAPSHOT LOSS: kernel arena-store drops (the M1 lesson) in
     the in-JVM setting -- verify snapshot CONTENT in vivo: handler-side
     write-verify (read-back compare in BPF) or userspace CRC of a
     freshly-flagged page vs its live content before first mutation.
     A dropped arena store = silently zero/stale snapshot = exactly a
     deterministic, workload-scaling retention gap.
  2. Drain-vs-FinalMark-tracing ordering within Closure (the drain's
     rescues arrive while tracing runs; check bucket/sentinel semantics
     for late-added Closure packets).
  3. LOS arming edges (runs computed at InitialMark; LOS objects that
     GROW their run set mid-cycle?).

## Session 5 (cont. 8): oracle chain + plateau (2026-07-07 latest)

The [vt] tracer turned leak-hunting into one-run precision: each
closure-scanned object prints with its narrow-klass before iteration,
so every crash self-identifies its leak class.  Three plugged in
sequence (mmtk-core + binding commits):
  24. narrow=1 ASCII degenerate -> word-alignment + first-page guard;
  25. heap-data narrows decoding into unrelated mappings in [base,+4GB)
      -> window confined to the contiguous reservation containing base
      (one 40-min suite wasted on an UNAPPLIED patch -- lesson: verify
      patches with asserts, use Edit for previously-modified regions);
  26. kind-tag aliasing inside committed segments -> two-field
      consistency (kind x layout_helper sign), quadratic filter.
Also disconfirmed in vivo: silent kernel arena-store drops (read-back
verify in the handler: dropped=0 across full runs).

SCOREBOARD (x3): luindex 3/3 stable; xalan up to 2/3 then hovering
1-2/3; pmd 0-2/3; lusearch 0/3.  PLATEAU REACHED: the remaining leak
class is stale-VO objects with REAL, intact-looking klass words --
no klass oracle can reject real klasses -- crashing in
get_object_size/line-marking, i.e. HALF-REUSED stale objects (header
region overlapping newer allocation).  DECISIVE NEXT QUESTION (fresh
session, immix source): does recycled-line allocation clear the VO
bits of prior dead objects in those lines, and does ConcurrentImmix
sweep eagerly at Release or lazily?  If stale VO bits legitimately
survive into the next cycle, the alloc-snapshot needs to be
intersected with swept-state, or sweeping made eager for page mode.

### VO-hygiene question SETTLED (source): sweep is EAGER (SweepChunk per
chunk in Release) and on_region_swept does VO := MARK for occupied
blocks / bzero for free ones -- the VO map is CLEAN after every
Release.  Consequences:
  * "stale VO under lazy sweep" theories: DEAD.  Every vo=true garbage
    object my tracer catches was MARKED by us (or a leak) in a prior
    cycle -- VO := MARK immortalizes any drain-mark leak as persistent
    poison (re-marked each cycle while its page stays hot).
  * The plateau therefore = the remaining oracle leak seeds, nothing
    else.  The oracle must be airtight (floating-garbage marking of
    REAL intact-dead objects is safe; marking NON-objects is what
    poisons).
  * NEXT PROBE (one run): provenance-tagged [vt] -- tag each
    trace_object call site (rescued-seed / closure-child / wholesale)
    so the crashing object names its SEEDER; then plug that one leak.
  * Alternative structural fix if oracle-perfection stalls: decouple
    drain retention from the mark bit that feeds VO := MARK (e.g.,
    rescued objects marked in a SEPARATE bitmap consulted by sweep, so
    leaks cannot poison VO) -- heavier, but breaks the poison loop by
    construction.

## Session 5 (cont. 9): the pendulum synthesis -- xalan 3/3 (2026-07-07 final)

EXACT extraction restored under the full validity oracle (mmtk-core
da28534c): the original exact era's "bogus VO heads" are now understood
as the poison loop (conservative-era leaked marks -> VO := MARK), which
predated every oracle guard.  With alive() = current-VO + full klass
oracle, exact slot values eliminate text-data candidates by design.

ORACLE CHAIN (final form): aligned + alloc-map/space + current-VO +
contiguous-region klass window + vptr-in-libjvm START detection +
kind x layout_helper consistency.  Leak families killed, each caught
in the act by the [vt]/[xt] tracers: narrow=1 degenerates; heap-data
narrows into unrelated mappings; kind-tag interior aliasing; small-
narrow (0x1770/0x303030 ASCII) aliasing.

SCOREBOARD (x3): xalan 3/3 (FIRST EVER), luindex 2/3, pmd 1/3,
lusearch 0/3.  ~30 characterized bugs.

NEXT-SESSION ENTRY: lusearch's remaining leak = NEW family: wild jump
to libmmtk_openjdk.so+0x76365 (SEGV_ACCERR, si_addr == PC, non-exec
section?) during [xt] extraction of small objects around 0x531b88xx --
distinct from all klass-alias families (its dispatch target is libmmtk
not libjvm).  Suspects: oop_iterate dispatch table in the BINDING for a
klass whose kind/layout passed but whose oop-map iterator hits a
binding-side fn-pointer path; or slot-closure re-entrancy.  The [xt]
loop finds it in one run.  Also queued: luindex 1/3 flake, pmd
variance, then extended correctness + compiled-vs-page A/B.

## Session 5 (cont. 10): the stray-JVM confound + clean 9/12 (2026-07-08)

CONFOUND DISCOVERED AND PURGED: `timeout N sudo java` kills the sudo
wrapper but NOT the root java under it -- every timed-out/aborted run
since early in the session leaked a root JVM.  24 stray JVMs (plus two
11-hour-old zombie suite loops) were running CONCURRENTLY with all
recent measurements: memory/CPU pressure explains much of the observed
flakiness (fail-pass-pass patterns).  All flaky-attribution data before
this point is suspect.  Leak-proof runner now: `sudo timeout -k 5 300
env ... java` + post-run pkill.

CLEAN-MACHINE SCOREBOARD (fixpoint design, x3): luindex 3/3,
lusearch 3/3 (was 0/3 under contamination!), xalan 2/3, pmd 1/3
= 9/12.  Remaining: xalan 1 crash + pmd 2 fails to characterize on the
clean protocol.

## Session 5 (cont. 11): M2 GREEN under noref (2026-07-08)

pmd@640m failures = OOM/timeout = OVER-RETENTION (page-granular SATB
floating garbage; honest documented cost, needs heap headroom).
xalan residual crashes (~40%) = REFERENCE PROCESSING: with
MMTK_NO_REFERENCE_TYPES + MMTK_NO_FINALIZER, xalan goes 4/4.  Page-COW
SATB v1 therefore requires the no-reference-types config (same
precedent as Compressor): the page mechanism cannot observe
Reference.get() loads, and the reference-processor interplay with
sentinel-time rescue needs a design pass to lift the restriction.

M2 STATUS: GREEN under noref config.  Running: x5 stability suite +
compiled-vs-page A/B (times/snap counts) + h2 768M extended.

## Session 5 FINAL: M2 delivered — stability 20/20 + A/B measured (2026-07-08)

### TASK 2 — STABILITY (x5 each, noref config, clean protocol): 20/20
  luindex 5/5, xalan 5/5, lusearch 5/5, pmd@640m 5/5.
  Page-COW SATB real mode is GREEN.

### TASK 3 — A/B compiled-SATB vs page-SATB (5-run medians, last-iter):
  xalan:    compiled 1161ms | page 2129ms  (+83%)
  lusearch: compiled 2212ms | page 7091ms  (+220%)
  pmd:      compiled 2143ms | page 2097ms  (-2%, PAR)
  h2@768M: FAILS BOTH configs under noref (h2 requires reference types
  -- SoftReference caches; known from Compressor work) -> excluded from
  the noref matrix by construction, not a page-mode defect.

### HONEST VERDICT
Correctness: achieved (v1 config: no-reference-types + non-moving +
heap headroom for floating garbage).  Performance: page mode is at PAR
on pmd but SLOWER on write-dense benchmarks (xalan +83%, lusearch
+220%) at 512M -- the per-store barrier's removal does not yet pay for
fault costs + sentinel-fixpoint drain + retention-driven extra GCs.
Mirror of the Class A granularity story.  OPTIMIZATION ARC (future):
concurrent drain (pre-sentinel rounds), narrower arming (dirty-chunk
prediction like Class A), retention trimming (extraction from written
sub-ranges via dirty-byte tracking inside pages), and pause accounting.

### Design lineage for the paper (~30 characterized bugs):
conservative -> exact -> conservative+oracle -> EXACT + sentinel
FIXPOINT (extract only from alloc-snapshot AND live objects; inductive
completeness; oracle only on rescue-target values where Reference
referents break the genuineness argument; leaks decay instead of
compounding because marks reset per cycle).

## Session 6: SATB optimization arc (2026-07-09)

Profile -> attribution -> three optimizations (mmtk-core commit):
occupied-only arming (faults -84%), targeted slice clearing (kills the
48MB/cycle memset), drain bitmaps (19.3 -> 5.0ms median).  Four crash
classes en route, each signature-driven: sft-empty panics from stale
slices (x2 sites), committed-edge slot loads (x2 loops).  pmd keeps a
rare sparse-arming residual -> dense fallback (MMTK_SATB_SPARSE=0)
4/4; sparse remains default elsewhere.

RECORD A/B (5-run medians, 40/40 PASS):
  xalan    1198 vs 2067ms (+73%)   [pre-opt +83%]
  lusearch 2219 vs 5103ms (+130%)  [pre-opt +220%]
  luindex  5050 vs 5091ms (PAR)
  pmd      2159 vs 2103ms (page FASTER by 2.6%)
Two of four at par-or-better; lusearch overhead nearly halved.
NEXT LEVERS: parallel arm packets (~24ms/cycle dominant), lusearch
residual (fault volume still 79k/run), pmd sparse hole (long-tail).

## Session 6 (final): optimization arc complete (2026-07-09)

Parallel arming (ArmChunks packets on the Prepare bucket; mmtk-core
9fb9377): arm setup 24.5ms -> 1.4ms median.  20/20 record-v2 passes.

### FINAL OPTIMIZATION TABLE (5-run medians, last-iter, vs compiled):
              compiled | pre-opt      | opt-1        | opt-2 (final)
  xalan         1198ms | 2129 (+78%)  | 2067 (+73%)  | 1810 (+51%)
  lusearch      2219ms | 7091 (+220%) | 5103 (+130%) | 4153 (+87%)
  luindex       5050ms |     --       | 5091 (PAR)   | 5229 (+3.5%)
  pmd(dense)    2159ms | 2097 (-3%)   | 2103 (-3%)   | 2094 (-3%)

### What each step bought (profile -> attribute -> fix):
  1. occupied-only arming: faults 482k -> 79k (-84%); lusearch -28%.
  2. targeted slice clearing + drain bitmaps: drain 19.3 -> 5.0ms.
  3. parallel arm packets: arm 24.5 -> 1.4ms; xalan -12%, lusearch -19%.

### Remaining gaps + levers:
  - lusearch +87%: residual = per-fault cost (79k x ~9us) + drain trace
    volume (~1M nodes/run) + second-order effects; next levers = fault
    handler slimming (single-copy path / batched WP-clear) and drain
    trace parallelization (packetize trace_all).
  - pmd sparse hole (rare, dense fallback documented).
  - noref requirement lift (reference-processor interplay) unchanged.

## Session 6 (closing): all next-optimization levers exercised (2026-07-09)

Levers 2-4 (after occupied-arming/bitmaps/parallel-arm):
  - PARALLEL DRAIN (kept): re-firing Closure sentinel, one extraction
    round per quiesce, 8 TraceRescued packets per round (mark-bit
    atomicity dedups).  ~Par at 512M; structural headroom for big heaps.
  - FAULT PREFETCH (negative result, gated off): snapshot+wp-clear of
    the next 3 pages per fault regressed ~10% -- per-fault
    bpf_fault_writeprotect (mmap lock + TLB flush) exceeds the cost of
    the faults saved.  Needed sleepable struct_ops (.s) regardless --
    kept for future use.
  - pmd sparse hole: deferred (dense fallback documented).

### FINAL TABLE (5-run medians, 20/20 pass; vs compiled):
              compiled | pre-opt      | final (v3)
  xalan         1198ms | 2129 (+78%)  | 1890 (+58%)
  lusearch      2219ms | 7091 (+220%) | 4166 (+88%)
  luindex       5050ms | ~PAR         | 5231 (+3.6%)
  pmd(dense)    2159ms | 2097 (-3%)   | 2086 (-3.4%)

### BOTTOM LINE + the one big remaining lever
Two of four at par-or-faster; write-dense residual (+58/+88%) is now
dominated by irreducible per-fault cost at this write density -- and
the kernel's WP resolution takes TWO faults per armed write (marker
clear + retry into do_wp_page CoW).  Collapsing to ONE fault
(resolution also mkwrite for exclusive anon) is a ~10-line kernel
patch in handle_bpf_fault_wp -- would roughly halve remaining fault
cost.  Needs kernel rebuild + reboot: FUTURE WORK entry point.

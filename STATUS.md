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
CORRECTNESS VALIDATED: 40/40 sweep runs pass (avrora fop h2 jython luindex
lusearch pmd sunflow xalan zxing x Barrier|Bpf|Uffd|Segv, -Xmx4G, -n 2).
All three backends pass DaCapo end-to-end with the compiled barrier
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

## Class B progress (2026-06-11)
- docs/class-b-design.md: full design. Vehicle = modify Compressor (NOT a new
  plan): its SecondRoots-before-Compact phase order IS the ART flip point, and
  stock STW Compressor becomes the apples-to-apples baseline.
- micro/test_flip: the flip primitive VALIDATED on bpf-fault — populate,
  mremap(MREMAP_DONTUNMAP) pages to a from-space alias, register the emptied
  range, materialize via in-kernel missing-fault copy from the alias.
  PASS at 1 GiB: mremap 0.38ms + register 0.63ms (the entire would-be pause
  cost), per-fault p50 2.6us, p999 10us, all contents verified.
- Next: B.0 in MMTk — per-region mremap in compact_region, copy objects into
  a 1MiB shadow via forward(), install pages (bpf: state+touch / uffd:
  UFFDIO_COPY), still STW; then B.1 resume-after-SecondRoots.

## Class A perf round 1 + LOS fix (2026-06-11 evening)
First quick numbers (-Xmx4G, -n 6 last iter, results/perf_quick.txt):
lusearch Bpf~parity with Barrier, uffd +15%, segv +30%; xalan/h2 all
page-WP configs ~2x SLOWER -> bpftrace showed dirty pages/GC small but the
conservative stash = ~97k LOS objects rescanned every nursery GC (xalan).
FIX (committed): WP-track LOS pages (coalesced runs, chunk-granular
registration via ensure_registered_range, spanning search bound 256MiB).
After fix: xalan Barrier 2831ms / Bpf 1129ms / Uffd 1228ms / Segv 1208ms —
page-grain remset BEATS object-grain modbuf (whole-array rescans) 2.5x.
Validation v2 sweep + perf rerun in results/correctness_sweep_v2.txt,
perf_quick_v2.txt (running). Immortal/nonmoving still conservatively
rescanned (were 0 objects on xalan).

## Class B.0 implemented (2026-06-12 session)
- mmtk-core (committed): `compact_faults` option (None|Bpf|Uffd) +
  util/compact_faults.rs + Compressor compact_region rework: per-region
  mremap flip into a linear arena, slide-compact at alias addresses
  (metadata at real addresses), stage + install (bpf: touch -> in-kernel
  arena copy; uffd: UFFDIO_COPY). Tail pages zero-fill via state array.
- shim: gc_b0_ops.bpf.c + gcb0_init/flip/state API in libgcbpf.so (built).
- NOT yet tested in the JVM (mock tests can't drive Compressor GC — stock
  Compressor fails mock_test_allocate_with_initialize_collection too).
  Separate JDK conf `b0test` building for testing without touching the
  image used by the running v2 validation. Test:
  sudo MMTK_PLAN=Compressor MMTK_COMPACT_FAULTS={Bpf|Uffd} java ...
- Open risks: cycle-2 mremap of a registered VMA (kernel may reject —
  would be a bpf-fault finding); uffd re-register per cycle (EBUSY?);
  last-region mremap if region partially mapped.

## Class B.0 VALIDATED (2026-06-12)
- fop@128M (many GC cycles), pmd, luindex, avrora all PASS on Compressor
  with MMTK_COMPACT_FAULTS=Bpf and =Uffd (stock None as control).
- Repeat-cycle mremap+register of bpf-fault regions works (no kernel issue).
- Fixed: uffd backend must UFFDIO_UNREGISTER each region after install —
  with UFFD_FEATURE_SIGBUS, beyond-cursor pages SIGBUS on TLAB zeroing
  instead of zero-filling (bpf needed no fix: state-0 zero-fills in-kernel).
- B.0 timings are expected to trail stock (mechanism validation, still STW).
- Next: B.1 — move install out of the pause: resume mutators after
  SecondRoots; GC sweep thread installs linearly; mutator faults on staged
  pages install in-kernel (bpf) / via SIGBUS handler + UFFDIO_COPY (uffd);
  unprocessed-page faults SIGBUS -> mutator stages the page ART-style.
  Requires: deferring forwarding.release() + AfterCompact LOS fixup +
  allocation-into-unmaterialized-regions guard (see docs/class-b-design.md).
- v2 perf table contaminated by concurrent B.0 builds/tests (my error);
  clean v3 run queued after v2 completes: results/perf_quick_v3.txt.

## Class A round-1 eval COMPLETE (2026-06-12, results/perf_quick_v3.txt)
Clean table (-Xmx4G, -n 6 last iteration, avg of 2 invocations, vs Barrier):
  lusearch: 2674 | Bpf 2450 (-8%) | Uffd 2803 (+5%) | Segv 2930 (+10%)
  xalan:    2797 | Bpf 1182 (-58%)| Uffd 1200 (-57%)| Segv 1181 (-58%)
  h2:       3711 | Bpf 5711 (+54%)| Uffd 6063 (+63%)| Segv 6391 (+72%)
  pmd:      1904 | Bpf 1990 (+5%) | Uffd 2113 (+11%)| Segv 2306 (+21%)
h2 diagnosed via USDT (results consistent across v1/v2/v3): 2K-8K dirty
pages/GC, ~282k objects rescanned per nursery GC (15.8M/56 GCs) — dense
small mature objects on dirty pages = page-grain remset worst case
(write-density tradeoff per Cracauer / card-size literature). xalan is the
mirror image: object-grain modbuf rescans whole large arrays, page-grain
wins 2.5x. Story: page-WP barrier wins on spatially-clustered writes,
parity on moderate (lusearch/pmd, where Bpf is the only backend at/below
Barrier), loses on dense-random-write (h2). Within page-WP backends, Bpf
is consistently fastest (h2: Bpf +54% vs Segv +72%).

## Class B.1 IMPLEMENTED + measured (2026-06-12 evening)
Concurrent install window works on both backends (wait-mode v0): xalan,
pmd, luindex, avrora, fop PASS with MMTK_COMPACT_FAULTS={Bpf|Uffd}
MMTK_COMPACT_CONCURRENT=true MMTK_NO_REFERENCE_TYPES=true
MMTK_NO_FINALIZER=true (Compressor plan, b0test JDK conf).
Bugs fixed en route: cursor preset must use the transducer's final
position (forward() of a non-object-start address is inexact); uffd
handler ops must tolerate ENOENT (GC unregisters after installing).

Pause measurement (scripts/measure_pauses.sh, uprobes on
mmtk_stop_all_mutators/mmtk_resume_mutators; xalan 1G, 18 GCs):
  stock STW Compressor: avg 17ms max 24ms
  B.1 Bpf/Uffd:         avg ~69ms max ~86ms  <-- WORSE, all in the flip
Root cause (measured precisely): 539 regions -> ~110 contiguous-run
mremaps = 60-66ms, ~0.45us/page = per-PTE page-table moves. Two kernel
causes: (1) registration splits heap VMAs at 1MiB region granularity,
permanently defeating 2MiB PMD-table moves (mremap of multi-VMA ranges
works on 6.17 but per-VMA); (2) armed VMAs (uffd-style ctx) force
marker-preserving per-PTE moves. Unregister-before-mremap measured: no
help (fragmentation persists). Arena PMD-phase-alignment done (ready for
the kernel fix). Stage throughput cost: pmd 3.9s vs stock 2.4s
(wait-mode spins; steal-mode is the known fix).

## KERNEL WORK NEEDED (the bpf-fault paper deliverables from Class B)
1. PMD-level page-table moves in mremap for missing-mode bpf-fault VMAs
   (no WP markers to preserve) + VMA re-merge after register/unregister so
   2MiB spans survive. Expected: flip 63ms -> ~1-2ms (O(PMDs) not O(pages)),
   making the B.1 pause ~5x BETTER than stock instead of 4x worse.
2. BUG: munmap of an mremap-destination VMA that inherited the fault ctx
   (MREMAP_DONTUNMAP source registered) corrupts subsequent fault handling
   (mutator crashes); reproduce via arena-slot munmap in finish_region
   (currently disabled under `if false` in compact_faults.rs).
3. Earlier list still stands: page-install command (UFFDIO_COPY equiv),
   sleepable wait-for-staging kfunc, chunked WP ops.

## Next steps
1. Kernel fix #1 above in /mydata/linux (build + install_kernel.sh +
   reboot node), re-measure B.1 pauses — the expected headline.
2. Steal-mode self-staging (mutator compacts the faulted region itself)
   for window throughput; per-page staging later.
3. Class A eval hardening (heap sweep, invocations, PGO) + h2 honest-limit
   analysis writeup; Class B same once kernel fix lands.

## B.1 pause RESOLVED to near-parity (2026-06-12 late)
Root cause of the 63ms flip found by kprobe+stack profiling: NOT PTE moves
(move_page_tables = 4.5ms total) but mremap(MREMAP_FIXED)'s implicit dest
unmap tearing down last cycle's from-space pages in the pause. FIX
(userspace, committed): MADV_DONTNEED the arena slot in finish_region
(concurrent). xalan@1G: pause avg 69ms -> 24ms / max 46ms vs stock STW
20.6ms / 24ms. pmd throughput 5.3 -> 3.1s (stock 2.4s, wait-mode).
Remaining gap + going BELOW stock needs the kernel change:
move_normal_pmd (mm/mremap.c:382) bails on !pmd_none(*new_pmd); after
DONTNEED the dest has empty-but-present page tables. Fix = detect empty
dest table, free it under the ptls, proceed with PMD move (the in-tree
comment literally suggests this). Alternative: reclaim empty PTs in
MADV_DONTNEED. Also still open: munmap-of-arena crash (timing/kernel?),
fs/userfaultfd.c:803 TODO (bpf_fault mremap notification).

## Crash investigation COMPLETE + virtme-ng harness (2026-06-12 night)
Two distinct B.1 crashes, both root-caused with a minimal no-JVM
reproducer (micro/test_flip_unmap.c):
1. SIGBUS (in-kernel): an armed missing-fault region whose from-space
   arena was released delivers SIGBUS — the handler's bpf_probe_read_user
   from the freed arena returns -EFAULT. PROVEN: armed+released=SIGBUS,
   unregister-first=PASS (single cycle). FIX committed: finish_region
   unregisters the region (bpf) before releasing the arena (uffd already
   did). Now matches the design's idempotency note.
2. UAF SIGSEGV (HotSpot interaction): munmap (vs MADV_DONTNEED) of the
   arena slot crashes DerivedPointerTable::update_pointers() at
   mmtk_resume_mutators — HotSpot transiently holds the arena address;
   munmap frees the VMA under it (SEGV_MAPERR at the arena range). KEPT
   MADV_DONTNEED (VMA persists). munmap (for full page-table teardown)
   needs deferral to a safe point — future work.
Final B.1: unregister-first + MADV_DONTNEED, xalan stable x3.

virtme-ng harness (no host reboot for kernel iteration):
- Installed via apt (vng, virtme-ng). Kernel rebuilt with 9p+virtiofs:
  scripts/config --enable CONFIG_NET_9P CONFIG_NET_9P_VIRTIO CONFIG_9P_FS
  CONFIG_VIRTIO_FS CONFIG_FUSE_FS CONFIG_VIRTIO_CONSOLE; make olddefconfig;
  make LLVM=1 CC=clang -j bzImage. (BPF_FAULT preserved; backup at
  /tmp/config.bpffault.bak.)
- scripts/vng_test.sh "<cmd>" boots /mydata/linux/arch/x86/boot/bzImage,
  shares /mydata, runs cmd. scripts/vng_crash_check.sh confirms the crash
  + fix inside the VM (boots in ~5s). vng exit codes unreliable -> grep
  stdout sentinels.
- This is the loop for the move_normal_pmd kernel fix: edit mm/mremap.c,
  make bzImage, vng_test.sh to measure flip cost, no node reboot.

## CORRECTION: no kernel change needed for the flip (2026-06-12 late night)
The earlier "63ms flip -> needs a move_normal_pmd kernel fix" was a
MISATTRIBUTION. Isolation experiments (micro/test_pmdmove.c,
micro/test_frag.c) + per-op timing in the real JVM disprove all three
suspected blockers:
- move_normal_pmd `!pmd_none(*new_pmd)` guard (CORE mm): does NOT fire.
  A full-range MADV_DONTNEED frees the dest's empty PTE tables, so
  pmd_none holds and PMD moves succeed. test_pmdmove: fresh dest 1.5ns/pg
  == DONTNEED'd dest 1.4ns/pg.
- VMA fragmentation from registration (bpf-fault-specific): does NOT
  happen. bpf_fault registration in 1MiB chunks leaves ONE VMA
  (test_frag: single vs chunked both vmas=1, 1.4-1.7ns/pg).
- uffd-wp per-PTE forcing (uffd_supports_page_table_move): already
  EXEMPTS VM_BPF_FAULT (userfaultfd_k.h:342).
Real JVM flip, instrumented separately: mremap=1.3ms + register=0.13ms =
~1.4ms for ~540MB live (xalan@1G, 541 regions / 113 runs). The earlier
~60ms was mremap(MREMAP_FIXED) synchronously tearing down the PREVIOUS
cycle's arena pages — already fixed (userspace) by releasing the arena
concurrently via MADV_DONTNEED in finish_region.
=> The move_normal_pmd guard IS core-mm-wide IF it were the issue, but it
   is NOT the issue. No kernel change required for the flip pause.
Remaining B.1 perf note: xalan pause 24ms vs stock 20ms is dominated by
the STW MARK phase (both plans), not compaction; the flip adds ~1.4ms.
The pause WIN shows up where the compact phase is a large fraction of GC
(big heaps / compaction-heavy workloads) — needs the right workload to
demonstrate, not a kernel change. Steal-mode (window throughput) and
heap-size sweeps are the real next steps.
Kernel items still open (NOT flip-related): munmap-of-arena UAF
(DerivedPointerTable race, use DONTNEED), fs/userfaultfd.c:803 bpf_fault
mremap-notification TODO.

## B.1 PAUSE WIN demonstrated on compaction-heavy h2 (2026-06-12 night)
measure_pauses.sh (uprobe stop/resume), results/classB/h2_pauses.txt:
            avg pause      max pause
  512M  None 254ms        318ms
        Bpf  180ms (-29%) 351ms (+10%)
        Uffd 177ms (-30%) 346ms
  768M  None 356ms        500ms
        Bpf  254ms (-29%) 580ms (+16%)
        Uffd 255ms (-28%) 540ms
=> B.1 concurrent compaction cuts AVG STW pause ~29% (the compaction phase
   moved out of the pause; mark stays STW). The MAX/tail is ~10-16% WORSE:
   a mutator faulting a still-pending page spins (wait-mode) -> tail latency.
   This is the steal-mode target. (xalan@1G showed no win: mark-dominated.)
Bpf vs Uffd pause ~equal (within noise): the pause = mark + flip; ALL fault
handling is concurrent (in the window), so the pause cannot reflect bpf's
in-kernel/no-signal advantage. bpf's edge is per-fault latency
(microbench: bpf 2.8-6.2us vs uffd-SIGBUS 6.6-34us) and shows in stall/
throughput, not pause. Caveat: bpf lacks UFFDIO_COPY (no page-install cmd),
so GC-worker bulk install faults each page while uffd does direct
UFFDIO_COPY -> narrows bpf's edge on the bulk path (kernel gap).

## B.1 window-stall finding: steal-mode is LOW priority (2026-06-13)
MMTK_WINDOW_STATS instrumentation (h2@512M, ~108 GCs):
- MOST windows: 0 mutator faults. Parallel GC-worker staging (Concurrent
  bucket drained by all ParallelGCThreads) finishes before mutators hit a
  still-pending page. So wait-mode causes ~no stall in aggregate.
- avg mutator_faults/window: Bpf 2, Uffd 6 (bpf's faster in-kernel install
  closes the window sooner -> fewer mutators catch a pending page; a clean
  bpf-over-uffd signal in the metric that actually exercises the handler).
- RARE faulting window: a mutator that does hit a pending page spins ~1.8M
  times (~1.8ms) until the sweep reaches its region. This is the only place
  steal-mode (mutator self-stages its region) would help: it converts a
  rare ~1.8ms spin into ~region-compaction work. Low frequency -> low
  aggregate impact, so steal-mode is deferred, not abandoned.
Note: h2@512M OOMs at -n>=5 (below h2's ~681M min heap); use -n 4 for GC
measurement, 768M+ for throughput.

## B.1 throughput: wait-mode is intrinsically costly, steal-mode REQUIRED (2026-06-13)
h2@768M -n4 throughput (last iter): stock 29.9s | Bpf 43.5s (+45%) |
Uffd 42.8s (+43%). At sustained load 237/479 windows have mutator faults
(NOT negligible — the 512M "0 faults" was a small-heap artifact).
Total spin = 79e9 spins ~= 237 CPU-seconds.
sched_yield (instead of busy spin_loop) did NOT help (Bpf 46s): rules out
CPU-starvation. The cost is intrinsic STALL LATENCY — a mutator faulting
region K is blocked until the address-ordered sweep REACHES K. Only fix =
steal-mode (mutator stages its own region immediately).
Feasibility CONFIRMED: HotSpot scan_object ignores the worker tls (_tls
unused), so stage_region can run on a mutator thread with a borrowed tls.
Plan: per-region atomic state (Unstaged/Staging/Done); mutator faulting K
CASes K Unstaged->Staging and stages it itself (or waits Done if another
stager is mid-K, bounded by one region not the whole sweep). VM-agnostic
SIGBUS handler calls a plan-registered steal callback.

## B.1 steal-mode WORKS — clean concurrent-GC tradeoff (2026-06-13)
Steal-mode (mutator stages its own faulted region in the SIGBUS handler)
recovers the wait-mode throughput regression:
  h2 768M -n4 last-iter:  stock 30.3s | Bpf 33.4s (+10%) | Uffd 33.5s (+11%)
  (wait-mode was Bpf +45%, Uffd +43%.)
The residual +10% is the inherent concurrent-compaction tax (staging
~500MB/GC contends with mutators for CPU/bandwidth) — expected, acceptable.
fop both backends PASS.
Livelock during bring-up was a one-line bug: the flip's
reset_region_staging + mark_region_live calls had silently failed to apply
(Python edit aborted on an assertion before writing), so no region was
ever claimable -> nothing staged -> mutators waited forever. Fixed.
=> B.1 net: ~29% STW pause reduction (h2) for ~10% throughput cost. A clean
   latency/throughput tradeoff, the classic concurrent-GC win, with
   bpf_fault providing the in-kernel fault path.

## B.1 FINAL (steal-mode) — Class B complete (2026-06-13)
h2 512M pauses (steal-mode, results/classB/h2_pauses_stealmode.txt):
  stock 259ms avg / 321ms max | Bpf 184ms (-29%) / 360ms | Uffd 184ms (-29%) / 350ms
Pause win held at -29% avg. Max +12% is mark-phase variance (the single
worst GC), NOT window-related — steal-mode's benefit is mutator
throughput/latency (the +45%->+10% throughput result), which the STW-pause
metric doesn't capture.
NET B.1: -29% avg STW pause for +10% throughput. Clean concurrent-GC
tradeoff on the Compressor plan, bpf_fault providing the in-kernel
page-materialization path. bpf vs uffd ~equal on pause (mark+flip
dominated); bpf's in-kernel edge shows in fewer window faults and
per-fault latency.

## Class A heap-sweep: the per-GC re-arming cost (2026-06-13 resume)
Heap sweep (heap = multiples of DaCapo G1 min heap; GenImmix copies so 2x
G1-min is ~1x GenImmix-min, GC-heavy) REVEALS strong heap-size sensitivity
that the earlier -Xmx4G numbers hid:
  lusearch 2x(38M): Barrier 6.2s | Bpf 13s | Uffd 24s | Segv 33s
  4G (verify): Barrier 2.3s | Bpf 2.7s (+17%, competitive)
ROOT CAUSE (measured, PROTECTSTATS instrumentation): at 38M lusearch does
10,888 nursery GCs; the protect/unprotect of the whole mature space each GC
= 11.1s of 13.1s total (DOMINANT; faults are 4.67M but cheap/absorbed in
mutator time). This is the fundamental O(mature-space)-per-GC re-arming
cost of page-granularity barriers (Cracauer/literature: good only when GC
is infrequent relative to mutation).
Optimization attempts:
- Remove prepare unprotect-all -> total 14.2s (WORSE): trades unprotect for
  O(promoted) GC-time promotion faults (~6s; recycled immix blocks fault).
- => no clean userspace win. The correct fix is to unprotect only the copy
  allocator's PROMOTION blocks (~1 block/GC) via an immix copy-allocator
  hook (cost O(promoted+dirty) not O(mature)). Substantial integration;
  documented as the key Class A optimization. NOT done.
HONEST Class A story: page-WP barrier is competitive/winning at LARGE heaps
(rare GC) for locality-friendly/array-heavy workloads (xalan -58% @4G), but
loses at TIGHT heaps (frequent GC) due to per-GC re-arming, and on
scattered-write workloads (lusearch). bpf<uffd<segv throughout. The
heap-size crossover is the result.

## Class A: incremental optimization TRIED, measured WORSE — root cause nailed (2026-06-13)
Implemented the promotion-block-granular optimization (unprotect only the
immix copy allocator's promotion blocks via an acquire-block hook, not the
whole mature space). Debugged to correctness (the gotcha: GenImmix's
promotion ImmixAllocator has the `copy` flag FALSE — that flag marks
*defrag*, not copy-context — so gating the hook on `self.copy` silently
skipped all promotion; dirty tracking is GenImmix-only where every
ImmixAllocator is a copy context, so the gate must just be "tracker
active"). Verified zero live-page misses + DaCapo passes.
RESULT: lusearch 38M Bpf 15.3s (vs chunk-granular 13.1s, Barrier 6.3s) —
WORSE. Reverted.
ROOT CAUSE (measured, bpftrace on bpf_fault_ops_link_writeprotect):
the WP syscall costs ~5-6us median (mode 4-8us), fat tail 32-128us for
4MB ranges. Finer granularity multiplies the WP CALL COUNT, and at 10,888
GCs/run that syscall overhead swamps the page-table-walk savings.
=> Three approaches all measured: chunk-granular (unprotect-all+protect-all,
   page-op bound) 13.1s = BEST; promotion-fault (no unprotect, on-demand)
   14.2s; promotion-block incremental (syscall bound) 15.3s. All ~2x
   Barrier at this GC frequency. The per-GC re-arming cost is fundamental;
   no granularity wins because either page-ops (O(mature)) or WP syscalls
   (O(promoted+dirty)) scale with GC frequency, which the compiled barrier
   avoids entirely.

## bpf-fault improvement opportunity (Class A paper finding)
Page-WP write barriers become viable at high GC frequency ONLY if the WP
operation is cheap. bpf-fault's BPF_LINK_FAULT_OPS_CMD writeprotect is
~5-6us/call. A BATCHED/VECTORED WP command (protect N ranges per syscall)
would amortize the fixed overhead and could flip the tight-heap result.
(Same family as the snapshot-finalize chunked-WP lesson.) This is the key
bpf-fault change Class A motivates.

## Class A heap-size CROSSOVER — complete (2026-06-13)
Full sweep (best-of-2, -n6 steady iter): results/classA/crossover.txt +
extreme.txt. Bpf (page-WP) vs Barrier (compiled ObjectBarrier):
  xalan (array-heavy, clustered writes):
    2x +63% | 64x +43% | 128x +4% | 256x -32% | 4GB -58%   <- CROSSES, WINS
  lusearch (scattered writes, high alloc, worst case):
    2x +106% | 64x +49% | 256x +6%                          <- only reaches parity
  h2: 2x +82%, 3x +77% (large min heap, stayed in losing regime)
TWO-DIMENSIONAL result:
  (1) Heap size: page-WP overhead falls monotonically as heap grows (fewer
      GCs -> less per-GC re-arming; the ~5us-WP-call bottleneck amortizes).
  (2) Write pattern: page-grain remset BEATS object-grain modbuf only with
      WRITE LOCALITY. xalan writes large arrays (clustered) -> page-grain
      wins once GC is rare; the compiled barrier pays per-store + rescans
      whole arrays. lusearch scatters writes -> page-grain ~= object-grain,
      reaches only parity.
=> The earlier -58% (xalan @4GB) is real and REPRODUCES on the current
   build. Bpf < Uffd < Segv throughout (mechanism ordering holds). The
   honest Class A claim: bpf_fault page-WP barriers win for write-clustered
   workloads at large heaps, reach parity for scattered-write workloads at
   large heaps, and lose at tight heaps (frequent GC) where per-GC WP
   re-arming dominates -- which a batched WP command would mitigate.

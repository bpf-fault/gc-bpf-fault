# Page-COW SATB: hardware snapshot barrier for concurrent marking

## Thesis
Cheap programmable faults (bpf_fault) resurrect virtual-memory-based
concurrent GC: replace ConcurrentImmix's **compiled SATB barrier**
(per-reference-store slow path + buffers) with **page-granularity COW
snapshots** taken in-kernel at WP-fault time.  Same plan, two barrier
implementations, direct A/B — the concurrent-marking mirror of Class A's
"page-WP replaces the compiled generational barrier".

## Mechanism (M1, VALIDATED — micro/gc_satb_ops.bpf.c + test_satb.c)
- Arm heap with bpf_fault WP.  First write to a page: handler copies the
  PRE-write page into a snapshot arena (via per-CPU scratch; probe_read
  cannot target arena) and sets a byte-per-page snap flag (arena atomics
  disallowed; own-byte stores race benignly), returns 0 → WP clears,
  write proceeds.  One fault per page per mark cycle.
- Measured: p50 8.9µs/snapshot fault @8T (fault + 2 page copies),
  3.5GB/s; WP-enable 12ms/256MB; arena pre-touch 160ms/320MB.
- BPF arena traps: kernel stores to UNPOPULATED arena pages are silently
  dropped (exception fixups, ~369µs of them per page) → arena must stay
  pre-touched.  V1 keeps the snapshot arena resident between cycles
  (heap-sized RSS overhead — measure; alternative: re-touch during
  concurrent pre-arm after MADV_DONTNEED).

## SATB soundness
- InitialMark pause scans roots (STW, unchanged).  Everything reachable
  at mark start must survive.
- Markers read the LIVE heap.  A ref R "hidden" by a mutator (copied then
  destroyed) was present in some page at mark start; destroying it is a
  write → that page's PRE-write content is snapshotted; the drainer scans
  snapshot pages and enqueues every plausible ref found (conservative:
  4-byte values decoding into the heap span with VO bit set → SATB
  packets, same ProcessModBufSATB type the compiled barrier flushes).
  Enqueued garbage = floating garbage, safe.
- New allocations during mark: allocate-black (exists:
  should_allocate_as_live in ImmixAllocator).
- VO bits persist during marking (cleared only at sweep), so the
  conservative filter is valid for mark-start refs.
- Weak refs/finalizers: disabled in our configs (MMTK_NO_REFERENCE_TYPES,
  MMTK_NO_FINALIZER); revisit before generalizing.

## Coverage
Compiled SATB covers every reference store; page mode must cover every
mutable heap slot:
- Immix space: WP-arm all chunks (chunk map) at InitialMark.
- LOS: WP-arm live-object page runs (Class A machinery).
- Immortal/nonmoving: NOT armed; instead FinalMark re-scans them
  wholesale as roots (they are immortal → treating all as live is exact;
  reuse Class A's ClosureObjectEnumerator stash).

## Phases (ConcurrentImmix, MMTK_SATB_PAGES=1)
1. InitialMark pause: roots; arm immix+LOS (v1 in-pause: ~36ms/768M —
   move to concurrent pre-arm later); mutator barrier stays NoBarrier
   the whole time (barrier selection gated at mutator creation).
2. Concurrent: marking as today; a self-re-enqueueing SATB drainer
   packet walks snap flags, scans flagged snapshot pages, emits
   ProcessModBufSATB packets, clears flags.
3. FinalMark pause: final drain; immortal/nonmoving rescan; disarm
   (WP-disable armed ranges); snap flags cleared.

## Pieces
- shim: gcsatb_* API (init/arm/disarm/flags+snap bases) wrapping
  gc_satb_ops (move BPF prog from micro/ into shim build).
- mmtk-core: util/satb_pages.rs tracker; ConcurrentImmix gating
  (barrier selection, InitialMark/FinalMark hooks, drainer packets).
- Baseline: ConcurrentImmix with compiled SATB (h2 768M pauses/tail/
  time) vs page mode vs stock Immix STW.

## Risks / open
- Arm cost in InitialMark pause (v1) — measure; concurrent pre-arm is
  the known fix (soundness: every page armed before root scan; the
  snapshot cut is per-page first-post-arm write).
- Mutator fault latency during mark (8.9µs × dirtied pages) — shows as
  mutator overhead; the A/B against per-store barrier cost is the point.
- Snapshot arena RSS (heap-sized worst case).
- Compressor integration (the original motivation) is future work once
  this validates; its mark is the same tracing machinery.

## M2 status (2026-07-07): WIP, parked with root-cause analysis

Integration built end-to-end (shim gcsatb API, satb_pages.rs tracker,
ConcurrentImmix wiring, binding gate).  luindex/pmd PASS; xalan/lusearch
fail.  Five bugs fixed en route (see mmtk-core 06c0b68e); the remaining
issue is FUNDAMENTAL to conservative snapshot draining on an exact VM:

**Conservative candidates can resurrect intact-dead objects** (stale VO
bits under lazy sweep).  Tracing them is unsafe not because they are
malformed (they are intact) but because their CHILDREN may point into
reused memory, and the exact tracer scans children unvalidated.
Candidate filters cannot fix this: dead-intact objects are
indistinguishable from live ones by VO/chunk state, and young-BLOCK
filtering over-rejects (recycled blocks mix mark-start-live objects with
fresh allocation).  Exact snapshot scanning (walk VO bits of the page,
scan object copies) collides with line recycling during mark (new VO
bits appear mid-mark; their slots read from the snapshot are pre-alloc
garbage).

**Sound design requirement identified**: the allocation frontier must be
tracked at LINE granularity (immix line = 256B) — objects/candidates in
lines recycled since mark start are post-snapshot by definition and can
be skipped exactly, while mark-start-live objects in the same block are
retained.  This needs an allocator hook logging line-range acquisitions
(same shape as the Class A block hook, one level finer).  Estimated as
the single remaining piece; parked in favor of idea 6 for now.

M1 (the kernel mechanism) is fully validated and stands on its own:
in-kernel pre-write snapshots at 8.9us p50, 3.5GB/s, no signals — the
enabling primitive uffd cannot match (its WP round-trip is 30-50us).

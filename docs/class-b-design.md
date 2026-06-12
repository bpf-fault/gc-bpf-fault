# Class B: Concurrent compaction via missing faults — design

## Vehicle decision

Modify the existing **Compressor** plan in mmtk-core rather than writing a new
plan. Reasons:

- Compressor's phase order is already flip-shaped. Its STW pipeline is:
  mark → CalculateForwarding (offset vector) → **SecondRoots (all roots
  rewritten to post-compact addresses)** → Compact (copy + fix refs) →
  Release. Roots are updated *before* any object is copied, by recomputing
  `forward(addr)` from the mark bitmap + offset vector. That means the exact
  point between SecondRoots and Compact is where ART's CMC resumes mutators —
  we make Compact concurrent and resume there.
- The forwarding metadata (mark bitmap, per-512B-block offset vector,
  `forward()`, `scan_marked_objects()`) is exactly the metadata a fault
  handler needs to materialize one to-space page: find from-space objects
  whose `forward()` lands in the page, copy them, rewrite their refs.
  Kermany–Petrank order preservation makes per-page enumeration well-defined.
- The space is region-structured (1 MiB contiguous regions,
  `RegionPageResource`, enumerable) — per-region
  `mremap(MREMAP_DONTUNMAP)` to a from-space alias works without a contiguous
  whole-space requirement.
- **The baseline comparison becomes self-contained**: stock Compressor
  (fully STW compaction) vs concurrent Compressor with bpf-fault vs the same
  with uffd (SIGBUS + UFFDIO_COPY, ART's production policy) vs
  mprotect+SIGSEGV. Same plan, same marking, same forwarding — the only
  variable is how the compaction window is hidden. No need to be competitive
  with G1; the claim is about the mechanism.

A brand-new plan would duplicate marking/forwarding/policy plumbing for no
benefit; the Compressor *is* the "baseline plan" to compare against.

## Phases of work

### B.0 — STW fault-materialization (mechanism validation)
Keep the GC STW, but replace the Compact packets' direct copying with:
per-region mremap(DONTUNMAP) to a from-space alias → register to-space range
with the fault mechanism → GC workers materialize every page (by touching
pages under bpf-fault, or UFFDIO_COPY under uffd) → verify heap identical to
stock Compressor. This validates metadata, the shim's missing-fault path, and
the page-materialization function with zero concurrency risk.

### B.1 — Concurrent compaction window (the result)
- In the pause: after SecondRoots completes, mremap regions aside, register
  to-space, **resume mutators**.
- A GC sweep thread materializes pages in address order.
- Mutator faults:
  - bpf backend: in-kernel handler consults a page-state array (BPF arena or
    mmapable map). `Staged` → copy the staged page from the shadow buffer
    into the kernel-provided page (zero-copy install), mark `Mapped`.
    `Unprocessed` → return error → SIGBUS → JVM signal handler runs the
    userspace materializer (ART-style: compact that page into the shadow
    buffer using forward()), marks `Staged`, returns → retry faults again →
    in-kernel install. (v2 moves the materializer itself into eBPF.)
  - uffd backend (ART policy): UFFD_FEATURE_SIGBUS; the mutator's SIGBUS
    handler materializes into a buffer and UFFDIO_COPYs it in.
  - segv baseline: PROT_NONE to-space, handler mprotects + copies (not
    atomic; same caveat as the microbenchmark — reported as such).
- Defer until the window closes: `forwarding.release()` (keeps mark bitmap +
  offset vector valid — currently released in Release stage, must move),
  LOS outgoing-reference fixup (AfterCompact), allocator cursor reset
  (mutator allocation during the window goes to fresh regions only —
  allocation into not-yet-materialized regions must be prevented).
- Close the window: when the sweep thread finishes, unregister, free
  from-space aliases (madvise/munmap), run the deferred Release work.

### Mutator allocation during the window
Compressor mutators bump-allocate into the same space. During the window,
allocation must not land in unmaterialized to-space pages. Simplest correct
rule: during the window, allocation goes only to regions *beyond* the
compacted set (fresh regions); the post-compact cursors are applied when the
window closes. (ART equivalently allows TLAB allocation beyond
black_allocations_begin_.)

## Metrics (vs. STW Compressor baseline)
1. GC pause time: stock Compressor's full compact pause vs the concurrent
   flip pause (mark is STW in both; report the compact-phase pause only and
   end-to-end pause distributions).
2. Mutator fault latency during the window (p50/p99/max, bpftrace).
3. Window duration (flip → fully materialized).
4. Throughput: DaCapo iteration times; latency-sensitive DaCapo metered
   percentiles.
5. Memory: transient from-space alias footprint over time.

## bpf-fault gaps to highlight (running list)
1. No userspace page-install command (UFFDIO_COPY equivalent): the bpf
   backend needs a second fault after staging (cheap, in-kernel) where uffd
   installs directly from the SIGBUS handler. An optional
   BPF_FAULT_INSTALL/COPY link command would remove the double fault — or
   sleepable handlers + a kfunc to wait for staging.
2. Missing-fault handler cannot block: unprocessed-page faults must bounce to
   userspace via SIGBUS (by design); fine for ART-style self-service, but a
   sleepable wait-for-state kfunc could express "park until GC stages this
   page" entirely in-kernel.
3. WP-range ops over large sparse regions: per-cycle protect of the whole
   mature space would benefit from a chunked/async variant (cf. snapshot
   finalize fix; relevant to Class A too).

## B.1 implementation design (settled 2026-06-12)

Pause-side (all STW):
1. Through SecondRoots unchanged (roots forwarded; forwarding trace is
   roots-only — verified trace_forward_root does not enqueue).
2. LOS ref fixup (AfterCompact's update_references over LOS) moves INTO the
   pause — it is metadata-only (forward()) plus LOS-object writes, no
   compressor-space dereferences.
3. FlipAll packet: per region — reset page states, set [start,
   predicted_to) to PENDING, flip (mremap + register). ~1ms/GB.
4. Cursor preset: post-compact cursor for each region computed in the pause
   from the offset vector as forward(cursor) (no copying needed), then
   page-aligned UP so window-time allocation never shares a page with
   staged installs (waste <= 4KB/region). reset_allocator also in pause;
   reset_cursor skipped in concurrent mode.
5. v0 runs with MMTK_NO_REFERENCE_TYPES=true MMTK_NO_FINALIZER=true:
   RefEnqueue/RefForwarding-style Release work dereferences forwarded
   compressor-space refs, which are not materialized until staged.
   (B.2: stage-on-demand for pause-tail work, or pre-flip enqueueing.)

Window (mutators running):
6. Stage packets in the Concurrent work bucket (ConcurrentImmix precedent):
   per region — slide-compact in the arena, set pages STAGED, install
   (bpf: touch -> in-kernel copy; uffd: UFFDIO_COPY), finish_region.
7. Page states: 0 zero-fill (beyond cursor) / 1 staged / 2 pending.
   bpf handler: 1 -> copy from arena; 0 -> zero-fill; 2 -> return error ->
   SIGBUS. Mutator SIGBUS handler (chained, installed by compact_faults):
   wait-mode v0 = spin until state==1, return (retry installs in-kernel);
   uffd: same but handler issues UFFDIO_COPY itself (EEXIST ok).
   Steal-mode (v1, ART-style self-service): faulting mutator CASes the
   region Unstaged->Staging and runs stage_region itself; risk = running
   scan_object/copy_to in signal context (ART does equivalent).
8. Window close: Concurrent-bucket sentinel — forwarding.release(), arena
   madvise, uffd unregister; clears window-open flag.
9. Next-GC guard: schedule_collection (or prepare) spins until the window
   flag clears — mark bitmap + offset vector stay valid for the whole
   window (next prepare bzeroes mark bits).

Metrics vs stock Compressor: compact-phase pause (stock: full copy; B.1:
flip-all + cursor preset only), window duration, mutator SIGBUS wait time
histogram, end-to-end benchmark time.

## B v2: in-kernel compaction + fixup — PROOF OF CONCEPT (2026-06-13)
micro/bench_kfixup + shim... micro/gc_kfixup_ops.bpf.c PROVE the kernel
mechanism: the missing-fault handler materializes each to-space page
entirely in eBPF — copies live objects from from-space AND rewrites their
reference fields to post-compaction addresses (forward() via GC-provided
old<->new maps). No userspace staging, no signal, no arena double-copy.
PASS across 8-168MB, 50-90% live; ~9.7us/page (64 objs + 128 refs/page);
168MB = 2.77M objs + 5.5M refs forwarded in-kernel. This is the GC analogue
of the paper's fault-time dynamic-linker relocation.

### What the microbench abstracts vs full MMTk integration
The microbench uses FIXED-SIZE objects + a flat old<->new forward table.
Full Compressor integration needs three harder pieces:
1. Variable-size objects: the handler must find object boundaries on the
   faulted page. Compressor's mark bitmap (object start/end bits) + offset
   vector give this; the handler scans the mark bitmap (bounded loop) like
   it scans the flat table now.
2. Real forward(): instead of a flat table, compute forward(addr) from the
   offset vector (cumulative live bytes/block) + mark bitmap — the same
   arithmetic the in-tree Compressor forward() and the paper's dynamic
   linker do. Implementable in eBPF (flat side-metadata reads + bounded
   mark-bit scan); the genuinely novel kernel piece.
3. Reference identification (the real blocker): which words on a page are
   pointers?  In HotSpot this needs the object's class -> oop map, which is
   impractical to traverse in eBPF.  SOLUTION: a REFERENCE BITMAP side
   metadata (1 bit/word = is-reference), set by the GC during marking (it
   already scans every object/slot).  ~heap/64 bytes overhead (16MB for a
   1GB heap).  The eBPF handler reads it per word — no HotSpot layout
   traversal needed.
=> Full integration is a substantial but well-scoped effort: add a
   reference bitmap to Compressor marking, port forward() + mark-bitmap
   object scan into the eBPF handler, drop the userspace staging path.
   The kernel mechanism (in-kernel copy + per-reference forward) is proven.

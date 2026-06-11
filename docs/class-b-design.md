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

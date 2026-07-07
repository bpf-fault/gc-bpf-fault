# ConcurrentImmix: heap corruption under write-protect-fault latency (draft upstream report)

## Summary

`MMTK_PLAN=ConcurrentImmix` (mmtk-core, compiled SATB barrier, OpenJDK 21
binding) exhibits heap corruption — dangling references, overwritten
reference fields — when the immix space is write-protected at
InitialMark via **stock userfaultfd WP-async** (`UFFD_FEATURE_WP_ASYNC`,
kernel ≥ 6.7) so that first writes to each page take a ~10µs in-kernel
fault instead of ~1ns.  No custom kernel and no handler logic is
involved: WP-async resolves faults entirely in-kernel; the only effect
is write latency on the first post-arm write per page.

The same configuration WITHOUT arming passes deterministically
(6/6 observed).  With arming: 0/9 across xalan/lusearch/luindex
(DaCapo 23.11, `-n 3`, 512M heap), typically crashing within seconds of
the first concurrent cycle.  Crash signatures vary run to run (SIGSEGV
in `ConcurrentHashMap.get`/`transfer` following a dangling reference;
`oop_iterate` over a corrupted object; faults on metadata ranges) —
consistent with a lost SATB edge or a pause/resume window race, not
with any single deterministic defect.

## Reproducer

1. OpenJDK 21 + mmtk-openjdk + mmtk-core with ConcurrentImmix.
2. At `Plan::prepare(InitialMark)` (mutators stopped), register the
   immix space's chunks with a userfaultfd configured with
   `UFFD_FEATURE_WP_ASYNC` and apply `UFFDIO_WRITEPROTECT` (mode WP).
   Disarm (`mode 0`) at FinalMark release.  ~60 lines; no fault handler
   thread needed.
3. `MMTK_PLAN=ConcurrentImmix java -XX:+UseThirdPartyHeap -Xms512m
   -Xmx512m dacapo xalan -n 3` → validation failure or SIGSEGV within
   the first iterations.

## Evidence that the fault mechanism is not the cause

- Identical corruption with an eBPF-based WP mechanism whose handler is
  a NO-OP, and with the full snapshot handler.
- Register-only (VMA flags set, no PTE write-protection): passes.
- Adversarial micros against the WP path all pass outside the JVM:
  16-thread same-page plain-store and atomic-RMW races across re-arm
  rounds; MADV_DONTNEED interleave; `read(2)` (`copy_to_user`) into
  armed pages with surrounding-content verification; full-range
  write-protect coverage checks (4096/4096 faults observed).
- THP and mTHP disabled throughout.

## Hypothesis

Slowing the first write to each page by ~4 orders of magnitude shifts
mutator/collector interleavings enough to expose a latent race in the
concurrent-marking machinery (e.g., around barrier activation at the
InitialMark boundary, unlog-bit bulk-set vs mutator resume, or
SATB-buffer flush vs FinalMark).  Fault counts show corruption follows
the FIRST arming closely (≈21 armed-page faults observed before crash).

## Sensitivity

Arming only **1/16 of chunks** still corrupts (2/2 fail, as does 1/4)
— broad slowdown is NOT required; a handful of delayed stores anywhere
in the heap suffices.  The window is an ordering assumption that any
single delayed store can violate, not a progress-balance effect.

## Why this matters beyond this configuration

Any VM-assisted write barrier (userfaultfd-based dirty tracking, CRIU
pre-copy, NUMA migration bursts, memory tiering) introduces exactly
this class of write-latency perturbation.  A concurrent GC that is only
correct when stores complete in nanoseconds is fragile against the
whole family of virtual-memory tools.

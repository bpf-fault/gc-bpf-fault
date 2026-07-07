# ConcurrentImmix under write-protect arming: investigation record (revised)

## Revision notice

An earlier draft of this report claimed an upstream ConcurrentImmix race
"exposed by WP-fault latency", based on failures reproducing under
mainline userfaultfd WP-async with the compiled barrier active.  A
drain-silenced A/B matrix subsequently RE-ATTRIBUTED the evidence:

1. **All bpf-config corruption was our own FinalMark drain** (the M2
   page-SATB sweeper): its liveness certificate admitted objects lazily
   swept and recycled during the cycle, and two accessors lacked bounds.
   With the drain silenced, write-protect arming of the whole heap
   during concurrent marking passes 7/7 with the compiled barrier —
   kernel bpf-fault WP path exonerated end-to-end.
2. **All uffd-config failures were harness bugs**: UFFDIO_REGISTER
   EBUSY asserts (cross-cycle re-registration; bpf/uffd VMA-ctx
   conflict).  The mainline uffd path was never implicated.

## What remains true and upstream-relevant

**FinalMark can lose SATB packets to the Concurrent bucket.**  At the
FinalMark stop, mutator barrier flushes run inside `stop_all_mutators`
— BEFORE `notify_mutators_paused` clears the marking state — so
`flush_satb` routes them to `WorkBucketStage::Concurrent` (observed: 32
packets in one xalan FinalMark).  `ConcurrentTraceObjects::flush`
routes children the same way.  The FinalMark pause never drains the
Concurrent bucket; `on_gc_finished` then re-opens it, and the packets
execute AFTER the pause with the marking state cleared, racing lazy
sweeping and running mutators.  Any load that delays marking (or
enlarges the marking-time backlog) widens exposure.

Fix (in this tree, `MMTK_SATB_NOFIX=1` reverts for A/B):
- `flush_satb` / `flush_weak_refs` / `ConcurrentTraceObjects::flush`
  route to Closure once `current_pause() == FinalMark`.
- `notify_mutators_paused(FinalMark)` migrates any Concurrent-bucket
  backlog into Closure (`WorkBucket::drain_to`).

We did not observe this defect *firing* as corruption in our workloads
(the observed corruption re-attributed as above), but the mis-routing
is structural and verified by event tracing.

## Methodology lesson

The differential oracle (compiled barrier active + passive page
machinery) correctly cleared the extraction logic, but the verify-mode
drain kept its own crashes in the failure signal, and the contaminated
uffd cross-check then pointed at the plan.  Separating layers required
silencing every piece of our machinery (drain off, no-op handler,
register-only, pulse/final arm phases) and re-running the full matrix.

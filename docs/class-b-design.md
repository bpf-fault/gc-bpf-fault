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

## B v2 UPDATE: arena edition + arbitrary-layout reference bitmap (2026-06-13)
micro/bench_kfixarena + gc_kfixarena.bpf.c (clang-20, native
addr_space_cast) strengthen the PoC on two axes:
1. REFERENCE IDENTIFICATION solved + demonstrated: references sit at
   object-specific word positions, found via a GC-provided REFERENCE BITMAP
   (1 bit/to-space word).  The handler forwards exactly the marked words --
   no fixed field offsets, no HotSpot oop-map traversal.  This is the real
   MMTk-integration blocker, now de-risked.
2. BPF ARENA for all shared state (from-space objects + forward tables +
   reference bitmap): direct pointer access, no probe_read, no per-element
   map lookup.  2.2x faster than the map PoC (4.4us vs 9.7us/page).
   Userspace populates via skel->arena->{from_space,new2old,old2new,refbits}.
PASS across 8-42MB; 660k objects + 1.3M refs forwarded in-kernel/run.

Remaining for full Compressor integration (all now well-scoped):
- Variable-size objects: replace fixed OBJ_SIZE with a mark-bitmap object
  scan to find boundaries on the page (bounded loop, same as scanning the
  flat new2old now).
- Real forward(): offset-vector computation instead of the flat old2new
  table (the paper's dynamic linker already proves table-driven fault-time
  computation in eBPF; same shape).
- GC side: set the reference bitmap during Compressor marking (it scans
  every slot already); share the forwarding metadata + reference bitmap +
  from-space with the handler via an arena; drop the userspace staging path.
The kernel mechanism (in-kernel copy + arbitrary-layout reference forward,
arena-backed) is fully proven.

## B v2 CAPSTONE: full Compressor-style in-kernel materialization (2026-06-13)
micro/bench_kompress + gc_kompress.bpf.c materialize each to-space page
entirely in-kernel from UN-SLID from-space, proving the pieces the
fixed-size PoC abstracted away: VARIABLE-SIZE objects (mark-bitmap word
runs), offset-vector forward() (per-block cumulative live + popcount, the
Compressor's real forwarding -- not a flat table), a per-page first-source
index, and a reference bitmap.  Arena-backed, clang-20.  PASS 1-128MB,
~18us/page; 128MB = 2M objs / 11M live words / 1.4M refs forwarded.

### Integration recipe (the handler needs five arrays; 3 already exist)
| handler array | Compressor source | status |
|---|---|---|
| from_space  | mremap'd from-space heap (B.1 flip)        | EXISTS |
| livebits    | COMPRESSOR_MARK side metadata              | EXISTS (re-encode start/end -> live-word, or adapt handler) |
| offvec      | COMPRESSOR_OFFSET_VECTOR side metadata     | EXISTS (calculate_offset_vector) |
| refbits     | NEW: set during marking (scans every slot) | TODO  |
| first_src   | NEW: derive in the offset-vector pass      | TODO (cheap) |

So live wiring = (1) add a reference bitmap set during Compressor marking;
(2) emit first_src during the offset-vector pass; (3) expose these four
side-metadata regions + from-space to the handler (arena, or probe_read of
MMTk side metadata); (4) adapt the handler to the Compressor's start/end
mark encoding and offset-vector format; (5) drop the userspace stage_region
copy.  No further kernel-mechanism unknowns.

### Verifier lessons (for the kernel-side write-up)
- nested outer(4096)xinner(64) loop -> "sequence of jumps too complex"
  (reported as -EFAULT): use bpf_loop() for the page scan so the callback
  is verified once.
- a loop counter spilled to the bpf_loop ctx loses its bound across an
  arena store: mask it to the page-word range (outw &= 511) before using it
  as a write offset.
- forward()'s block loop with an unbounded base (oldw from a ref value):
  bound oldw (< total_words) and use a fixed 0..63 iteration count.

## B v2 MMTk wiring attempt — architectural findings (2026-06-13)
Started the live Compressor wiring (reference bitmap). Added inert
infrastructure that builds + passes DaCapo (luindex, standard + B.1):
- `COMPRESSOR_REFBITS` side-metadata spec (spec_defs.rs) + `REFBITS_SPEC`
  + `mark_reference_slot` (forwarding.rs).
- `Slot::slot_address()` provided trait method (vm/slot.rs), overridden for
  `SimpleSlot` and `OpenJDKSlot` (returns the field address, tag stripped).

Three concrete blockers found (these reshape tasks #8-#10):
1. **B.1 runs only with COMPRESSED oops.** Uncompressed -> the Compressor
   space spans >64 GiB -> `compact_faults::init` asserts (compact_faults.rs:84,
   the staging arena is sized to the span). So references are 4-byte
   compressed oops; the in-kernel handler must decompress -> forward ->
   compress, and the bitmap wants 4-byte granularity.
2. **Staging uses an ALIAS arena.** `stage_region_idx` (compressorspace.rs:319)
   copies each marked object to `alias_new = obj + delta` and calls
   `update_references` on the *aliased* object. So slot addresses there are in
   the staging arena, OUTSIDE the compressor-space side-metadata range ->
   storing the bitmap via `REFBITS_SPEC` SIGSEGVs. (Confirmed: a side-metadata
   write at alias addresses crashed the JVM.)
3. Therefore the reference bitmap for B.1 cannot be MMTk side metadata. It
   must live **in the staging arena**, populated at staged positions during
   `stage_region_idx`, and travel with the staged page to the handler.

### Revised in-kernel-forwarding design for B.1 (well-specified now)
- `stage_region_idx`: copy objects to the alias arena (as today) but DO NOT
  forward; instead, while scanning each object's slots, set a ref bit in an
  arena-resident bitmap at the staged slot position and leave the compressed
  old oop in place.
- shim eBPF handler (install path): for each ref-bit dword on the staged
  page, decompress the 32-bit oop (base+shift), forward old->new (offset
  vector or a forward map shared in the arena), recompress, write.
- This moves the per-slot forward work off the staging thread into the
  fault-time handler, overlapped with mutator resume — the B v2 win — while
  the variable-size compaction stays in userspace (already correct in B.1).
- The CAPSTONE microbench (gc_kompress) already proves the kernel-side
  offset-vector forward + bitmap + page materialization; the remaining work
  is the compressed-oop encode/decode and the arena-resident bitmap plumbing.

## B v2 task #9 DONE: arena-resident reference bitmap populated during staging (2026-06-13)
The reference bitmap now lives in its own mapping (compact_faults.rs:
`refbitmap`, 1 bit / 4-byte compressed-oop slot = span/32 bytes, lazy), NOT
MMTk side metadata — resolving the alias-arena addressing blocker.

- `CompactFaults::{set_ref_bit, ref_bit, clear_ref_bits, refbitmap_base}`
  index by `(to_space_addr - space_base) >> 2`.
- `CompressorSpace::update_references_staged` (new): during `stage_region_idx`,
  while sliding each object into the alias arena and forwarding its slots, it
  also records each non-null reference slot's *to-space* address
  (`alias_slot - delta`) in the bitmap.  `clear_ref_bits` wipes the region's
  bits each cycle first.
- `Slot::slot_address()` now returns the field address for compressed slots
  too (the earlier COMPRESSED->None guard suppressed everything).

VALIDATED: DaCapo luindex (Compressor + compact_faults=Uffd) PASSES with
~110k reference slots recorded per cycle; no out-of-range writes (positions
within the mapped bitmap = within the span). The bitmap marks exactly the
slots `update_references` forwards, at their post-compaction positions.

### Remaining (task #10): forward via the bitmap at install time
- Flip `update_references_staged` to NOT forward (leave the old compressed
  oop), and forward at install instead.
- Uffd: in `handle_window_fault`/`install`, before `uffd_copy(page, alias)`,
  forward the arena page — for each set ref bit in [page,page+4KB), make a
  VMSlot at the arena alias address, `load()` (decompresses) -> `forward()` ->
  `store()` (recompresses).  Needs a VM callback (compact_faults is VM-
  agnostic) and runs in SIGNAL CONTEXT (forward() = side-metadata reads, slot
  load/store = plain mem; lock-free, so feasible but must stay async-signal-
  safe).
- Bpf: the true in-kernel path — port the forward into the shim eBPF handler
  (compressed-oop decode base+shift -> offset-vector forward [proven in
  gc_kompress] -> encode), reading the refbitmap (passed via refbitmap_base).

## B v2 task #10 (userspace): deferred bitmap-driven forward VALIDATED (2026-06-13)
Reference forwarding is now MOVED OFF the staging path and driven entirely by
the Class B v2 reference bitmap, validated end-to-end in real MMTk:

- `MMTK_COMPACT_DEFER_FORWARD=1`: `update_references_staged` no longer
  forwards (leaves the old compressed oop in the arena); it only records the
  reference bitmap.
- At install time, `install_page_uffd` copies the staged arena page into a
  private scratch buffer, calls `CompressorSpace::forward_buf` (rewrites each
  ref-bit slot: VMSlot::from_address -> load [decompress] -> forward() ->
  store [recompress]), then `UFFDIO_COPY`s the forwarded buffer to to-space.
- IDEMPOTENT by construction: the arena stays un-forwarded (the source of
  truth), each fault forwards its own copy -> race-free. (The first attempt
  forwarded the arena in place and double-forwarded under concurrency,
  crashing B.1; the scratch buffer fixed it.)
- New plumbing: `Slot::from_address`, `StealHandler::forward_buf`,
  `defer_forward()`, `CompactFaults::install_page_uffd`.

VALIDATED (DaCapo, Compressor + compact_faults=Uffd + defer):
- B.0 (STW install): luindex, fop, lusearch, avrora PASS.
- B.1 (concurrent, forward runs in SIGNAL CONTEXT): luindex, lusearch,
  avrora, xalan, h2, jython, pmd PASS — 7/7, output-validated.
This proves the reference bitmap is correct + complete and that the in-kernel
handler's job (forward each bitmap-marked slot during page materialization)
produces correct results in a real GC, concurrently.

### Remaining: port forward_buf into the BPF eBPF handler (true in-kernel)
All components now de-risked. The shim handler must, per staged page:
decompress each ref-bit dword (compressed-oops base+shift, passed in) ->
offset-vector forward (proven in gc_kompress) -> recompress -> write, reading
refbitmap via `CompactFaults::refbitmap_base`.  No remaining unknowns; the
uffd path is the executable reference semantics.

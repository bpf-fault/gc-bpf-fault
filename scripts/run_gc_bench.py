#!/usr/bin/env python3
"""GC benchmark driver: runs DaCapo under MMTk configs and natively emits
structured JSON records (like the VM-snapshot harness), instead of raw logs
parsed after the fact.

Class A (dirty tracking):   GenImmix + MMTK_DIRTY_TRACKING={Barrier,Bpf,Uffd,Segv}
Class B (concurrent compaction): Compressor + config in
  {None (STW), Uffd, Bpf (v2 eager), R1 (in-kernel)}

One JSON record per invocation, appended (and flushed) as each run finishes,
so the output is crash-safe and reruns are resumable: existing (bench,
config, heap, invocation, kind) records are skipped.  Raw JVM/bpftrace
output is kept next to the JSON and referenced from each record.

Run under sudo (BPF attach + bpftrace need root).

Examples:
  ./run_gc_bench.py --klass B --bench h2 --heap 768M \
      --configs None,Uffd,Bpf,R1 --invocations 5 --pauses
  ./run_gc_bench.py --klass A --bench xalan --heap 4G \
      --configs Barrier,Bpf,Uffd,Segv --invocations 5
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

# The MMTk-enabled JDK build and the DaCapo jar, both produced by
# install_gc.sh.  Defaults assume this repo is the gc-bpf-fault submodule
# of the bpf-fault artifact, with openjdk/ and dacapo/ as siblings of it;
# GC_JDK / GC_DACAPO override them, and --jdk / --dacapo override those.
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART_DIR = os.path.dirname(REPO_DIR)
DEF_JDK = os.environ.get(
    "GC_JDK", os.path.join(ART_DIR, "openjdk/build/mmtk/images/jdk"))
DEF_DACAPO = os.environ.get(
    "GC_DACAPO", os.path.join(ART_DIR, "dacapo/dacapo-23.11-MR2-chopin.jar"))
# libgcbpf.so is dlopen'ed by mmtk-core; point it at this repo's build
# unless the caller has already chosen one.
DEF_SHIM = os.environ.get(
    "MMTK_BPF_SHIM", os.path.join(REPO_DIR, "shim/libgcbpf.so"))

CLASS_A_CONFIGS = {"Barrier", "Bpf", "Uffd", "Segv"}
CLASS_B_CONFIGS = {"None", "Uffd", "Bpf", "R1"}


def config_env(klass, config):
    if klass == "A":
        return {"MMTK_PLAN": "GenImmix", "MMTK_DIRTY_TRACKING": config}
    env = {"MMTK_PLAN": "Compressor",
           "MMTK_NO_REFERENCE_TYPES": "true", "MMTK_NO_FINALIZER": "true"}
    if config == "Uffd":
        env.update(MMTK_COMPACT_FAULTS="Uffd", MMTK_COMPACT_CONCURRENT="true")
    elif config == "Bpf":
        env.update(MMTK_COMPACT_FAULTS="Bpf", MMTK_COMPACT_CONCURRENT="true")
    elif config == "R1":
        env.update(MMTK_COMPACT_FAULTS="Bpf", MMTK_COMPACT_CONCURRENT="true",
                   MMTK_COMPACT_INKERNEL="1")
    return env


def pause_probe(jvm, java_cmd):
    """bpftrace program timing every stop-the-world window (entry of
    mmtk_stop_all_mutators -> entry of mmtk_resume_mutators)."""
    prog = f"""
uprobe:{jvm}:_ZL22mmtk_stop_all_mutatorsPv14MutatorClosure {{ @t = nsecs; }}
uprobe:{jvm}:_ZL20mmtk_resume_mutatorsPv /@t/ {{
  $us = (nsecs - @t) / 1000;
  @pause_us = hist($us); @max_us = max($us); @avg_us = avg($us);
  @gcs = count(); delete(@t);
}}"""
    return ["bpftrace", "-e", prog, "-c", " ".join(java_cmd)]


def parse_hist(text):
    unit = {"": 1, "K": 1024, "M": 1024 ** 2}
    return [[int(m[0]) * unit[m[1]], int(m[2]) * unit[m[3]], int(m[4])]
            for m in re.findall(
                r"\[(\d+)([KM]?), (\d+)([KM]?)\)\s+(\d+) \|", text)]


def parse_run(text, kind):
    iters = [int(x) for x in re.findall(r"in (\d+) msec", text)]
    passed = [int(x) for x in re.findall(r"PASSED in (\d+) msec", text)]
    r = {"passed": bool(passed),
         "last_iter_ms": passed[-1] if passed else None,
         "iters_ms": iters}
    if kind == "pauses":
        def grab(k):
            m = re.findall(r"@%s: (\d+)" % k, text)
            return int(m[-1]) if m else None
        r.update(pause_avg_us=grab("avg_us"), pause_max_us=grab("max_us"),
                 gcs=grab("gcs"), pause_hist=parse_hist(text))
        # A crashed JVM still yields "@gcs: 0"; require real collections
        # before treating the bpftrace run as a pass.
        r["passed"] = r["passed"] or bool(r["gcs"])
    return r


def load_records(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--klass", choices=["A", "B"], required=True)
    ap.add_argument("--bench", required=True)
    ap.add_argument("--heap", required=True, help="e.g. 768M or 4G")
    ap.add_argument("--configs", required=True,
                    help="comma-separated, e.g. None,Uffd,R1")
    ap.add_argument("--invocations", type=int, default=3)
    ap.add_argument("-n", "--iterations", type=int, default=6)
    ap.add_argument("--pauses", action="store_true",
                    help="also run a bpftrace pause-measurement invocation set")
    ap.add_argument("--jdk", default=DEF_JDK)
    ap.add_argument("--dacapo", default=DEF_DACAPO)
    ap.add_argument("--out-dir", default=None,
                    help="default: results/ next to this script")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--scratch-dir", default=None,
                    help="working directory for DaCapo's extracted data"
                         " (default: <out-dir>/.dacapo-scratch)")
    args = ap.parse_args()

    configs = args.configs.split(",")
    valid = CLASS_A_CONFIGS if args.klass == "A" else CLASS_B_CONFIGS
    bad = set(configs) - valid
    if bad:
        sys.exit(f"error: invalid class-{args.klass} configs: {sorted(bad)}")

    out_dir = args.out_dir or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "results")
    out_dir = os.path.abspath(out_dir)
    log_dir = os.path.join(out_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    out = os.path.join(
        out_dir, f"gc_benchmark_class{args.klass}_{args.bench}.json")
    records = load_records(out)
    # Only completed runs count as done: a failed configuration must be
    # retried on the next invocation, not skipped and silently reported as
    # a success.
    done = {(r["config"], r["heap"], r["invocation"], r["kind"])
            for r in records if r["results"].get("passed")}

    scratch = os.path.abspath(
        args.scratch_dir or os.path.join(out_dir, ".dacapo-scratch"))
    os.makedirs(scratch, exist_ok=True)

    java = os.path.join(args.jdk, "bin", "java")
    if not os.path.isfile(java):
        sys.exit(f"error: no JDK at {args.jdk}"
                 " (run install_gc.sh, or set GC_JDK/--jdk)")
    if not os.path.isfile(args.dacapo):
        sys.exit(f"error: no DaCapo jar at {args.dacapo}"
                 " (run install_gc.sh, or set GC_DACAPO/--dacapo)")
    if not os.path.isfile(DEF_SHIM):
        sys.exit(f"error: no bpf_fault shim at {DEF_SHIM}"
                 " (run install_gc.sh, or set MMTK_BPF_SHIM)")
    jvm = os.path.join(args.jdk, "lib", "server", "libjvm.so")
    kinds = ["throughput"] + (["pauses"] if args.pauses else [])
    failed = []

    for inv in range(1, args.invocations + 1):
        for config in configs:
            for kind in kinds:
                key = (config, args.heap, inv, kind)
                if key in done:
                    print(f"Skipping config: class {args.klass} "
                          f"{args.bench} {args.heap} {config} {kind} "
                          f"(invocation {inv}/{args.invocations})",
                          file=sys.stderr)
                    continue
                java_cmd = [java, "-XX:+UseThirdPartyHeap",
                            f"-Xms{args.heap}", f"-Xmx{args.heap}",
                            "-jar", args.dacapo, args.bench,
                            "-n", str(args.iterations)]
                cmd = (pause_probe(jvm, java_cmd) if kind == "pauses"
                       else java_cmd)
                env = dict(os.environ)
                env["MMTK_BPF_SHIM"] = DEF_SHIM
                env.update(config_env(args.klass, config))
                log = os.path.join(
                    log_dir,
                    f"{args.bench}.{args.heap}.{config}.{inv}.{kind}.log")
                print(f"Running config: class {args.klass} {args.bench} "
                      f"{args.heap} {config} {kind} "
                      f"(invocation {inv}/{args.invocations})",
                      file=sys.stderr)
                t0 = time.time()
                with open(log, "w") as lf:
                    try:
                        subprocess.run(cmd, env=env, cwd=scratch,
                                       stdout=lf,
                                       stderr=subprocess.STDOUT,
                                       timeout=args.timeout)
                    except subprocess.TimeoutExpired:
                        lf.write("\n[harness] TIMEOUT\n")
                text = open(log, errors="replace").read()
                rec = {"class": args.klass, "kind": kind,
                       "bench": args.bench, "config": config,
                       "heap": args.heap, "invocation": inv,
                       "n_iters": args.iterations,
                       "wall_s": round(time.time() - t0, 1),
                       "timestamp": int(t0), "log": os.path.relpath(log, out_dir),
                       "results": parse_run(text, kind)}
                # Drop any earlier failed record for this key rather than
                # accumulating duplicates across retries.
                records = [r for r in records
                           if (r["config"], r["heap"], r["invocation"],
                               r["kind"]) != key]
                records.append(rec)
                tmp = out + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(records, f, indent=1)
                os.replace(tmp, out)
                status = "ok" if rec["results"]["passed"] else "FAIL"
                if not rec["results"]["passed"]:
                    failed.append(f"{config}/{kind}/inv{inv}")
                print(f"  -> {status} {rec['results'].get('last_iter_ms')}ms",
                      file=sys.stderr)
    print(out)
    # Exit nonzero so the eval script reports a failure rather than a green
    # checkmark over a results file with no usable data in it.
    if failed:
        print(f"error: {len(failed)} run(s) failed: {', '.join(failed)}",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

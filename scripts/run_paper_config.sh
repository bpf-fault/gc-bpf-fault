#!/bin/bash
# Rerun the Class B table rows under the paper's stated system config
# (SMT off, swap off, ASLR off), via the structured harness.  Restores
# machine state on exit.  Results land in results/gc_benchmark_classB_*.json.
set -u
S=$(dirname "$(realpath "$0")")
restore() {
	echo on | sudo tee /sys/devices/system/cpu/smt/control > /dev/null
	sudo swapon -a 2>/dev/null
	echo 2 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null
	echo "[papercfg] machine state restored"
}
trap restore EXIT
echo off | sudo tee /sys/devices/system/cpu/smt/control > /dev/null
sudo swapoff -a
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null
echo "[papercfg] SMT off, swap off, ASLR off"

# h2 first: it carries the headline numbers.
sudo "$S/run_gc_bench.py" --klass B --bench h2 --heap 768M \
	--configs None,Uffd,R1 --invocations 5 --pauses -n 6 --timeout 1800
for spec in "pmd 336M" "xalan 80M" "lusearch 128M"; do
	set -- $spec
	sudo "$S/run_gc_bench.py" --klass B --bench "$1" --heap "$2" \
		--configs None,Uffd,R1 --invocations 3 --pauses -n 6 --timeout 900
done
echo "[papercfg] PAPERCFG DONE"

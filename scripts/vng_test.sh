#!/bin/bash
# Boot the bpf_fault kernel under virtme-ng (no reboot of the host node)
# and run a command inside, sharing /mydata over 9p.  Use to iterate on
# kernel changes: rebuild bzImage, then vng_test.sh "<cmd>".
#
# The kernel must be built with 9p/virtiofs (scripts/config --enable
# CONFIG_NET_9P CONFIG_NET_9P_VIRTIO CONFIG_9P_FS CONFIG_VIRTIO_FS;
# make olddefconfig; make bzImage).  Exit code is unreliable through vng,
# so callers should grep stdout for explicit PASS/FAIL sentinels.
set -u
KDIR=${KDIR:-/mydata/linux}
BZ=${BZ:-$KDIR/arch/x86/boot/bzImage}
TIMEOUT=${TIMEOUT:-180}
MEM=${MEM:-8G}
CMD=${1:-"echo no-command"}

cd "$KDIR"
timeout "$TIMEOUT" vng -r "$BZ" -m "$MEM" --user root -- bash -c "
  mount -t bpf bpf /sys/fs/bpf 2>/dev/null
  $CMD
" 2>&1

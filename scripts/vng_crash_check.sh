#!/bin/bash
# Run inside the vng guest: checks the arena-release SIGBUS crash and its
# unregister-first fix.  Emits explicit sentinels (vng exit codes are
# unreliable).
#   test_flip_unmap <pages> <cycles> <do_munmap> <unregister_first>
mount -t bpf bpf /sys/fs/bpf 2>/dev/null
cd /mydata/gc-bpf-fault/micro || exit

check() { # <label> <args...>
  local label=$1; shift
  if ./test_flip_unmap "$@" 2>&1 | grep -q "PASS"; then
    echo "CRASHCHECK $label VERDICT=survived"
  else
    echo "CRASHCHECK $label VERDICT=crashed"
  fi
}

# Armed region + released arena, no userspace unregister: SIGBUS today,
# unless the kernel learns to tolerate a missing handler read of a freed
# source (the candidate kernel fix).
check armed_released_no_unregister 256 1 1 0
# Userspace fix: unregister the region before releasing the arena.
check unregister_first             256 1 1 1

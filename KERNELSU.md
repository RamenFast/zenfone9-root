# KernelSU on a bootloader-locked Zenfone 9 — plan

Goal: replace the "SuperSU experience" with **KernelSU** (the modern root manager) on a device whose
bootloader cannot be unlocked. Boot-image patching is therefore impossible, so the only viable route is
**late-load / LKM mode**: from a session that already has temporary root, load the KernelSU kernel
module with `insmod`-equivalent machinery and then install the manager app.

## Why plain `insmod` won't work

Every prebuilt `.ko` records a fixed vermagic (e.g. `5.10.252-dirty …`), which will never equal this
device's `5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032`. They also have ~200 undefined symbols
(`kallsyms_lookup_name`, `selinux_state`, `policydb_*`, `stop_machine`, …) and an empty `__versions`.
`ksud`'s loader handles both: it relocates undefined symbols itself from `/proc/kallsyms` (marking them
`SHN_ABS`), calls `init_module()`, and if the kernel complains about the vermagic it rewrites the
`.modinfo` string in memory and retries. So: **use `ksud late-load`, not `insmod`.**
`insmod -f` is not a substitute — it needs `CONFIG_MODULE_FORCE_LOAD=y` in the target kernel (GKI does
not set it) and does nothing about the unresolved symbols.

The one hard gate that can still stop this: `CONFIG_MODULE_SIG_FORCE=y` (a signature rejection has no
fallback). Check that first.

## Pre-flight checks (read-only, from the rooted session)

```sh
echo 1 > /proc/sys/kernel/kptr_restrict
zcat /proc/config.gz | grep -E 'MODULE_(FORCE_LOAD|SIG_FORCE)|KPROBES|KALLSYMS_ALL|CFI_CLANG'
grep -wE 'sys_call_table|kallsyms_lookup_name|selinux_state|policydb_read' /proc/kallsyms
getenforce
```

## Artifacts (all from the same release as the manager APK — the kernel verifies the manager by APK
certificate hash baked into the `.ko`, so they must match)

| file | where |
|---|---|
| `KernelSU_v3.3.0_32601-release.apk` | https://github.com/tiann/KernelSU/releases/tag/v3.3.0 |
| `ksud-aarch64-linux-android` (embeds all eight `*_kernelsu.ko` + `ksuinit`) | same release |
| `lkm-aarch64-android12-5.10_kernelsu.ko` (sha256 `5ca70d23…ce03a`) | same release |
| KernelSU-Next `android12-5.10_kernelsu.ko` (alternative) | https://github.com/KernelSU-Next/KernelSU-Next/releases/tag/v3.3.0 |
| SukiSU-Ultra `aarch64-android12-5.10-lkm.zip` (alternative) | https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/tag/v4.2.0 |

This device is a GKI variant (`AI2202`, `VARIANT=gki`), so KMI `android12-5.10` is the right target and
`ksud` auto-detects it from `5.10.205-android12-9-…`.

## On-device procedure

1. Install the manager APK first (same release as the `.ko`).
2. Load the module from the rooted session:
   ```sh
   KSUD=/data/local/tmp/ksud        # or the libksud.so extracted from the APK
   chmod 755 "$KSUD"; mkdir -p /data/adb/ksu
   setsid "$KSUD" late-load --kmi android12-5.10 --allow-shell </dev/null >/tmp/ksud.log 2>&1 &
   grep -q kernelsu /proc/modules && echo loaded
   ```
   `--allow-shell` matters: late-load **re-enables SELinux enforcing** and grants shell root directly.
3. ksud then creates `/data/adb`, installs itself as `/data/adb/ksud`, extracts busybox, applies sepolicy,
   and runs its late-load / system.prop / metamodule / post-mount / service / boot-completed stages.

## Caveats

- **Late-load loses:** initrc injection, ksud kprobe hooks, safe mode, boot-log capture,
  Magisk-coexistence checks. (Documented at https://kernelsu.org/guide/module.html#late-load-mode)
- **SELinux context gotcha** ([PR #3354](https://github.com/tiann/KernelSU/pull/3354)): ksud must reset
  its stdin/stdout/stderr after loading, otherwise cmd transactions are blocked because the fd still
  carries `u:r:su:s0` instead of `u:r:ksu:s0`. Redirect ksud's stdio to a log and force-stop + restart the
  manager afterwards. Tell-tale symptom: `kernelsu` in `/proc/modules` and shell `su` works, but the
  manager reports "not installed".
- **Not persistent across reboot:** module, hooks and runtime sepolicy are lost; `/data/adb/*` state
  survives but nothing triggers it at boot.
- **Persistence without unlocking = re-load only:** after each boot, re-obtain temporary root (see
  `ROADMAP.md`) and re-run `ksud late-load`. Precedents for exactly this model:
  [ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) (SM8475 / 5.10 offsets already
  extracted for a sibling SoC) and
  [CVE-2026-43499-root-KernelSU](https://github.com/woshimaniubi8/CVE-2026-43499-root-KernelSU).

## Status

Not yet attempted on hardware: our temporary root needs a fully reliable kernel-text patch first
(see `ROADMAP.md` §5b/§6), because `ksud late-load` must run from a *stable* rooted session.


## Round 8 (verified 2026-09-17): USABLE root + KernelSU early-late-load

Temporary root is now *usable*, and the KernelSU LKM loads. Recipe, in order:

1. **Permissive** — clear BYTE 0 of `selinux_state` (`0xaaa40b98`): the byte IS `enforcing` (byte 1 is
   `checkreqprot`; clearing byte 1 does nothing — that was the first mistake). Hot data does not take a
   device store every time: it needed 5 attempts before `getenforce` flipped to `Permissive`. The oracle
   is the kernel's own `getenforce`, never our readback.
2. **Root** — 16-dword shellcode in place at `__do_sys_capset` (`0xa8145af0`, cold syscall; all
   encodings PC-relative => slide-independent, no runtime literals, no cave):
   `stp x29,x30 / str x19 / bl prepare_creds / cbz / mov x19,x0 / add x0,x19,#4 /
    adrp x1,<init_cred page> / add x1,x1,#0xae4 / mov w2,#0x4c / bl memcpy / mov x0,x19 /
    bl commit_creds / mov w0,wzr / ldr x19 / ldp / ret`
   i.e. copy `init_cred+4 .. +0x50` (all eight ids, securebits, all five cap sets) into a
   `prepare_creds()` copy of OUR cred. `security` sits far beyond +0x50, so **our SELinux SID is kept**.
   Result: `uid=0 euid=0 gid=0`, `CapEff 000001ffffffffff`, `context=u:r:shell:s0`.
   Dwords: `a9be7bfd f9000bf3 9400faa2 b4000140 aa0003f3 91001260 f0013341 912b9021 52800982
   97fb66db aa1303e0 9400fc5e 2a1f03e0 f9400bf3 a8c27bfd d65f03c0`.
3. **Trigger** — any `capset()` call (`/data/local/tmp/call_capset`).

### What that unlocked (measured, same run)

| op as the rooted process | before (Enforcing) | now |
|---|---|---|
| write `/data/local/tmp` | DENIED | **OK** |
| write `/sdcard` (FUSE) | DENIED | **OK** |
| read `/proc/kallsyms` | DENIED | **OK** (`_text` visible; values 0 until `kptr_restrict=0`) |
| list `/data/data` | DENIED | **OK** |
| write proof page | DENIED | **OK** |
| `init_module` | EPERM | **ENOEXEC = permitted** |

### KernelSU

`ksud late-load --kmi android12-5.10 --allow-shell` (tiann v3.3.0, `ksud-aarch64-linux-android`,
`lkm-aarch64-android12-5.10_kernelsu.ko` sha256 `5ca70d239f955139db23cd3028e578975cd038a7f2dc5f54ab4498a13f7ce03a`):

```
kernelsu 200704 0 - Live 0x0000000000000000 (O)
```

The module loads. Still open at the time of writing: ksud's userspace stages (`/data/adb/ksud` came back
`Permission denied`, `ksud.log` empty - likely the permissive flip reverting under vendor services
mid-session), verifying `su`, and installing the manager APK.

### Negative results (do not retry these)

* `commit_creds(&init_cred)` => uid 0 in the **kernel** domain: every userspace op denied.
* `avc_has_perm` text patch: it is **hot**, the patched entry is often never seen => ineffective.
* `avc_denied` (`0xa88ba524`) patch: lands and verifies, changes nothing (it only gates the audit /
  EACCES conversion, not the decision), and the device rebooted soon after.
* `avc_has_perm_noaudit 0xa88bb5d8`; `prepare_creds 0xa8184580`; `memcpy 0xa801f680`;
  `commit_creds 0xa8184c94`; `init_cred 0xaa7b0ae0`; `selinux_state 0xaaa40b98`; cave `0xa801c7e4`
  (7 NOP dwords only - too small for shellcode, fine for the 2-dword `mov w0,wzr; ret` gadget).


## Round 9 (2026-09-17): permissive root fully usable; KernelSU LKM loads but is not yet a stable end state

With the round-8 recipe (permissive byte 0 + 16-dword cred shellcode), **every probe now returns
ALLOWED** as the rooted process — the whole "root that can't do anything" problem is gone:

```
PROBE open /proc/kallsyms                ALLOWED
PROBE write /data/local/tmp              ALLOWED
PROBE write /sdcard (FUSE)               ALLOWED
PROBE open /dev/kgsl-3d0                 ALLOWED
PROBE open /dev/block/by-name/boot_a     ALLOWED
PROBE exec /system/bin/id                ALLOWED
PROBE init_module (bogus image)          rc=-1 errno=8 (Exec format error) => PERMITTED
CapEff: 000001ffffffffff   context=u:r:shell:s0
```
Evidence: `logs/usable-20260917-191347/{root.txt,rootcheck.txt,ksu.txt}`.

Also verified: with root + permissive, `setenforce 0` succeeds through the **kernel's own** selinuxfs
interface (not just our patched byte), i.e. the permissive state becomes official.

### KernelSU v3.3.0 (manager APK installed first, then late-load)

```
kernelsu 200704 0 - Live 0x0000000000000000 (O)      # /proc/modules, reproduced twice
```
The LKM **does load**. What does not yet work:

* `ksud.log` stays empty and `/data/adb` returns EACCES *even as uid 0 with permissive SELinux and
  CAP_DAC_OVERRIDE working elsewhere* (writes to /data/local/tmp and /sdcard succeed in the same
  session, so this is not a capability problem).
* `su` is not found, so KernelSU's own root path is unverified.
* With the module live the system degraded (activity manager unreachable, `cmd: Can't find service:
  package`), and the interrupted restore had to be abandoned; a reboot is the failsafe.

So late-load gets the module in, but ksud's userspace stages (which create `/data/adb/ksud`, busybox,
sepolicy, and the `su` plumbing) must complete before this counts as "KernelSU installed".

### Next steps (in order)

1. Run `ksud late-load` in the *foreground* with stdio captured, from a permissive root session, and
   read its actual error (the empty log is the main unknown).
2. Work out the `/data/adb` EACCES (label/ownership vs. our process) - possibly create it as
   `root:root 0700` with the expected `adb_data_file`/`ksu_file` label *before* loading.
3. Only then verify `su -c id` from an unpatched shell, and take a fresh on-screen proof screenshot
   (this round's `screencap` came back 0 bytes because the system was already degraded by then).
4. Keep the session's permissive flip sticky while ksud runs (vendor services re-assert enforcing).


## Round 10 (2026-09-17): KernelSU late-load VERIFIED WORKING (su -> u:r:ksu:s0)

From a permissive + rooted session, `ksud late-load --kmi android12-5.10 --allow-shell` does the whole
job - it loads the module *and* completes its userspace install:

```
/proc/modules : kernelsu 200704 0 - Live 0x0000000000000000 (O)
/data/adb     : ksud (6286568 B), ksu/bin/                 # created by ksud itself
```

Verified from a **fresh, unpatched adb shell** (uid 2000, no exploit involved, SELinux Enforcing):

```
$ adb shell id
uid=2000(shell) ... context=u:r:shell:s0
$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
kernel log: KernelSU: sys_execve su found
```

That is KernelSU's own root path working with no help from our exploit. Evidence:
`logs/ksu-verified/{ksu-state.txt,ksu-manager*.png,root-proof-*.png}`.

### The key insight that explains round 9

**Late-load re-enables SELinux enforcing** (its documented behaviour). Under Enforcing, the *exploit's*
root - uid 0 but SID still `u:r:shell:s0` - loses `dac_override`, so shell-owned paths
(`/data/local/tmp`, and `/data/adb` by label) come back EACCES despite uid 0 + full caps, while
root-owned `/data/adb` stays reachable. Consequences:

* after late-load, do post-load work through KernelSU's `su` (`u:r:ksu:s0`), not the exploit's uid 0;
* `scripts/root-usable.sh` should re-flip permissive *after* late-load if the exploit is to keep doing
  privileged work;
* round 9's "empty ksud.log + /data/adb EACCES" was this, not a broken module.

### Still open (both cosmetic/verification, not functional)

1. The manager APK's UI stays on its splash screen (even after force-stop + restart, i.e. the
   documented late-load caveat). `su` works regardless.
2. A *fresh* on-screen root proof was not captured this round: `cmd statusbar expand-notifications` is
   ineffective from shell/root here, my swipes opened the app drawer instead, and Chrome cannot read the
   root-written `/sdcard/root-proof.html` (FUSE assigns it `u0_a181 media_rw 0660`). The screen evidence
   captured is the KernelSU app icon/manager. Next attempt should `su -c 'chmod 644 /sdcard/root-proof.html'`
   (or write the page via `su` to a world-readable path) before opening it, and close the app drawer
   (BACK twice) before swiping the shade from y=0.

### Root status: repeatable

Three separate runs of `scripts/root-usable.sh` landed the patch 16/16 verified dwords and produced a
usable uid-0 session; `PHASE=stop` leaves the session live for interactive work
(`adb shell "/data/local/tmp/call_capset sh -c '...'"`), `KEEP=1` keeps it live too. Reboot remains the
failsafe: after reboot the text is pristine, SELinux is Enforcing, and the module is gone (not persistent).

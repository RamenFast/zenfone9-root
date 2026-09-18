# Zenfone 9 / CVE-2025-21479 — STATUS

## ✅ TEMPORARY ROOT ACHIEVED AND VERIFIED

```
[call_capset] rooted (uid=0 euid=0 selinux ctx unchanged); exec id
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

Root lands in the **kernel SELinux domain** (`init_cred`'s SID), i.e. effectively unrestricted.
Root is **proven and verified**, but re-applying it is **not yet reliable** — the underlying primitive
is a race (TTBR0 update vs command execution) and KGSL throttles a context after 3 GPU faults in 3 s.
Observed: the 13-dword patch landing 13/13 on some runs (root verified) and 2/13 on others; a *partial*
patch can panic the kernel (one spontaneous reboot). Reboot restores pristine text. Engineering the
fault rate down is the remaining work (see ROADMAP §4/§6) — it is a reliability problem, not a science one.

Repeatable via `scripts/root-now.sh id` (or `sh`) once hardened. Root is per-process and RAM-only — a fresh shell
stays uid 2000, and a reboot clears it. That is inherent to this CVE lineage (all public
CVE-2025-21479 outcomes are temporary root).

**Current device state (verified):** boot_completed=1, bootloader `locked=1`, SELinux **Enforcing**,
kernel text pristine (`0xd503233f` at `__do_sys_capset`), media backup intact (44 files, MD5-verified).
Nothing persistent was modified; every experiment's effects were RAM-only and are cleared by reboot.

## The chain (four stages, each verified)

1. **CVE-2025-21479 triggers** — userland SDS packet issues `CP_SMMU_TABLE_UPDATE`; kernel log echoes our
   TTBR0 in `GPU PAGE FAULT … FAULTING BLOCK: CP`. First ASUS device in the public record for this CVE.
   Microcode is permanently vulnerable: SPL 2024-07-05 predates the June-2025 Qualcomm fix, ASUS is EOL.
2. **Deterministic physical-address leak** — `perf_event_paranoid = -1`, so a hardware watchpoint on a page
   we own returns `PERF_SAMPLE_PHYS_ADDR`. Page-granular, reproducible. This replaced the blind spray
   hunt entirely (upstream/the fork used readable `pagemap`, which this build denies).
3. **Arbitrary physical R/W** — fake page table at a *known* physical address:
   `READBACK target=0x9d3bda040 value=0xc0ffee11 SELFTEST-PASS` (reproduced twice, hash-verified binaries).
4. **Root** — offline symbol resolution from the extracted kernel image + KASLR slide derived on-device
   (`init_task.cred` → `init_cred` runtime VA; cross-checked against `sys_call_table` high dword) →
   patch `__do_sys_capset` with `commit_creds(&init_cred)` shellcode → call `capset()` → uid 0.

## Key requirements and safety rules (learned the hard way)

- **SELinux must be Permissive** for stage 4; under Enforcing the rooted process is silently killed.
  Permissive also means the device is wide open — restore Enforcing when not in use.
- **Restore the patched text immediately.** Leaving it live while permissive caused a spontaneous reboot
  (any `capset` caller silently becomes kernel-root). Reboot is the failsafe.
- **Read before write**; verify writes by readback; **never leave injected PTEs live** (that also rebooted
  the device once).
- **Verify pushed binary hashes** (a stale `cheese_pa` produced silent no-output runs).
- **Do not touch secure/TZ memory** (reading `0x80000038` reboots); the DRAM high bank (0x800000000+) is
  normal memory, and physical layout is `file offset == physical - 0xA8000000`.
- **Writes: one dword per process run.** Multi-dword writes in one command hit `EPERM` from KGSL.
- **Reads: poll the result slot, not the marker** — the `CP_MEM_TO_MEM` copy can land after the marker.
- Memory pressure panics this kernel (`panic_on_rcu_stall=1`): 4 GB / 8 GB sprays rebooted it. The
  known-PA port does no spray and never crashed.
- **Post-reboot access** (no PIN on device): `adb shell 'input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard'`.

## Not achieved / not achievable by these means

- **Bootloader unlock:** every conventional route refused (`oem unlock`, `flashing unlock`,
  `flashing unlock_critical` → permission denied/unknown command; `get_unlock_ability`=0; ASUS removed the
  Developer-options toggle; the community's `oem auth-hash` prerequisite is absent on this build).
  Root cannot re-sign `vbmeta`, so **custom ROMs still require ASUS's cooperation** — root ≠ unlock.
- Persistence: not yet implemented (see ROADMAP §7 for the realistic options; app-level re-root is
  unverified because `perf_event` is normally denied to untrusted apps).
- The kernel-VA self-map (bulk/coherent physical access) still fails with `SEGV_MAPERR` despite the PTE
  being verified in DRAM — cache/walk-cache visibility, not a wrong table. Not needed for root as shipped.

## Meanwhile, the original goal is also solved without root

Internal audio capture for phosphor dev: scrcpy playback capture verified with a synthetic 997 Hz tone
(950–1050 Hz band RMS −26.3 dB vs 80–200 Hz −49.1 dB) → `artifacts/audio-capture-test.opus`. On-device
equivalent: Android's consent-based `AudioPlaybackCapture` API.

## Artifacts

`ROADMAP.md` (durable handoff: constants, procedure, gotchas, open paths) · `src/cheese_pa.c` (GPU
primitive + POKE/PROBE/SELFTEST/ROOT modes) · `src/pa_leak.{c,h}` · `src/call_capset.c` ·
`src/host_kallsyms.c` (offline resolver) · `scripts/root-now.sh`, `scripts/patch-dwords.sh` ·
`artifacts/` (SHA-256-verified ASUS OTA, extracted partitions, `kernel.Image`) ·
`~/Videos/Zenfone9-backup-NhZOcgfg`.

---

## ROOT ACHIEVED (round 6-7) — and the precise limitation

**Working configuration** (`scripts/root-final.sh`), verified on hardware repeatedly:

```
capset(NULL,NULL) -> 0 errno=0 (Success)
uid=0 euid=0 gid=0  *** ROOT ***
CapEff: 000001ffffffffff
```
On-screen proof: `logs/final-20260917-183323/root-proof-notification.png`.

Recipe: GPU actively rendering (verified) → stage `mov w0,wzr; ret` in an unreachable code cave and
branch `avc_has_perm`'s entry to it with ONE atomic dword → patch `__do_sys_capset` with the 3-dword
P1 tail-call (`adrp x0,<init_cred>; add x0,x0,#off; b commit_creds`) → trigger `capset()` in a fresh
process. Every write accepted only on a SEPARATE-process readback. Three writes instead of thirteen
is what keeps the window short enough that the device survives.

**Limitation (measured, round 7).** Although the process has uid 0 and the full capability set, every
practical operation is DENIED: `/proc/kallsyms`, writes to `/data/local/tmp` and `/sdcard`, opening
`/dev/kgsl-3d0`, opening block devices, `execve`, and **`init_module` → EPERM**. Reason:
`commit_creds(&init_cred)` moves the task into the **kernel** SELinux domain (init_cred's SID), and
Android's policy grants that domain *fewer* userspace permissions than the `shell` domain we started
in. So uid 0 alone is not useful here — the domain is what matters.

**Consequence: KernelSU late-load is blocked in this configuration** (module loading is EPERM), and so
is `exec`-based tooling.

**Two facts that shape the fix:**
1. Text patches take effect for **cold** functions (`__do_sys_capset` — the shellcode executed) but not
   for **hot** ones (`avc_has_perm` is called on every permission check and stays in the I-cache, so our
   branch there never runs). Patching a hot function cannot be relied on.
2. The SELinux *state* byte cannot be written from the GPU (hot data line; the CPU's writeback clobbers
   the store — see §5c).

**Next step (clear):** keep our own SELinux domain while gaining uid 0. A text-only patch can
`bl prepare_creds` (which *copies our current cred*, preserving our `shell` SID), zero the uid/gid
fields and fill the capability set, then `bl commit_creds`. That yields root **with the shell domain's
permissions** — the ability to write `/data`, exec, open device nodes — which is what both the proof
and KernelSU need. The offsets for the uid block and the capability set can be found by reading our own
cred (reads are reliable) after locating it via the `init_task` walk with the VA→PA delta.


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

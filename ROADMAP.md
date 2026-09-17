# 🗺 ROADMAP — Zenfone 9 root project (durable handoff)

**Project dir: `/home/ben/Dev/zenfone9-root/`** (symlinked at `~/Dev/ClaudeWorkspaces/zenfone9-root`
per the filing-cabinet rule). Everything below is verified on-device unless marked otherwise.

---

## 1. Where we are

**Temporary root: ACHIEVED and verified on 2026-09-17.**

```
before: uid=2000 euid=2000 gid=2000
capset(NULL,NULL) -> 0 errno=0 (Success)
after:  uid=0 euid=0 gid=0  *** ROOT ***
```

Repeatable with one command: `scripts/root-now.sh id` (or `... sh` for a root shell). It patches,
roots, then **always restores the original kernel text** (trap-protected).

Bootloader unlock: **NOT achieved, and not achievable by any conventional route** (ASUS removed the
tool, deleted the Developer-options toggle, and refused `oem unlock` / `flashing unlock` /
`unlock_critical`; the advertised `oem auth-hash` prerequisite is absent on this build).
**Root ≠ unlock**: verified boot is enforced by the bootloader against fused keys, so ROM flashing
still needs ASUS's cooperation. Root gives runtime control, not ROM capability.

---

## 2. The verified chain (four stages)

| # | Stage | Status | Key artifact |
|---|---|---|---|
| 1 | **CVE-2025-21479 trigger** — SDS/RB misclassification lets userland issue `CP_SMMU_TABLE_UPDATE`, hijacking the GPU's TTBR0 | ✅ confirmed (kernel log echoes our TTBR0 in `GPU PAGE FAULT … FAULTING BLOCK: CP`) | `src/cheese.c` |
| 2 | **Deterministic physical-address leak** — `perf_event_paranoid = -1`, so a hardware watchpoint on a page we own returns `PERF_SAMPLE_PHYS_ADDR` = that page's physical address | ✅ page-granular, reproducible | `src/pa_leak.h`, `src/pa_leak.c` |
| 3 | **Arbitrary physical R/W** — fake page table placed at a *known* PA (no spray lottery) | ✅ `READBACK … value=0xc0ffee11 SELFTEST-PASS` ×2 | `src/cheese_pa.c` |
| 4 | **Root** — offline symbol resolution + validated KASLR slide → patch `__do_sys_capset` with `commit_creds(&init_cred)` shellcode → call `capset()` | ✅ uid 0 verified, text restored after | `src/call_capset.c`, `scripts/patch-dwords.sh`, `scripts/root-now.sh` |

Stage 1–3 need no root; stage 4 needs only physical R/W. **Perf leak is the unlock** — upstream and the
iQOO fork both got their spray addresses from readable `pagemap`, which this build denies (PFNs zeroed).

---

## 3. Constants (verified this session — subject to change per boot where noted)

```
kernel physical base        0xA8000000     (arm64 "ARM\x64" magic at +0x38; file offset 0x38 matches)
image_size / file layout    file offset == physical offset - 0xA8000000   (text_offset = 0)
sys_call_table              0xaa129578     (physical; note: index→symbol mapping NOT yet confirmed)
__do_sys_capset             0xa8145af0     (patch target; first dword 0xd503233f = paciasp)
__arm64_sys_capset          0xa8145ac4     (link VA 0xffffffc008145ac4)
init_task                   0xaa79bec0     (task_struct; real_cred +0x778, cred +0x780)
init_cred                   0xaa7b0ae0     (link VA 0xffffffc00a7b0ae0)
commit_creds                0xa8184c94     (link VA 0xffffffc008184c94)
selinux_state               0xaaa40b98     (byte 0 = enforcing: 0x01010001 → 0x01010000 disables)
swapper_pg_dir              0xaa472000     (also found independently by cheese's own scan at +0x2472000)
tramp_pg_dir / idmap_pg_dir 0xaa470000 / 0xaa46d000
KASLR slide                 PER BOOT — last observed 0x2E41000000. Re-derive from init_task.cred
                            high dword (see §5); do NOT hardcode across reboots.
```

Offline resolution: `src/host_kallsyms.c` parses kallsyms from the extracted image; add symbol names
to its list and re-run. `tools/btf_offsets.py` exists but this image has **no BTF** (the `9f eb 01`
hits are instruction bytes) — struct offsets were found by scanning the image instead.

---

## 4. Root procedure (what actually works, and why)

**SELinux must be Permissive first — verified both ways:**
- Permissive → works, and the root process lands in **`u:r:kernel:s0`** (it inherits `init_cred`'s SID,
  i.e. the *kernel* domain — effectively unrestricted, stronger than a typical Magisk root):
  `uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0`
- Enforcing → the process is **silently killed** (`exit=1`, no output): the patched call bypasses the
  SELinux hook, so the process gains uid 0 without a valid domain transition.

⚠️ **Footgun, observed:** leaving the patched text live *while SELinux is permissive* is dangerous — any
process that calls `capset` silently becomes kernel-SID root, and in practice that took the device down
(spontaneous reboot). Always restore the text promptly; a reboot is the failsafe (text is reloaded from
flash, `selinux_state` re-initialised to Enforcing).

One command does the whole cycle (permissive → patch → run as root → restore text + SELinux):
`scripts/root-now.sh id` / `scripts/root-now.sh sh`

**Reliability status — read this before using it.** The *procedure* is verified end-to-end (root was
achieved and confirmed: `uid=0(root) … context=u:r:kernel:s0`, `capset() -> 0`). Re-applying it is
**not yet reliable**, because of the TTBR0-update race and KGSL's fault throttle described in §6: the
13-dword patch has landed completely on some runs (root verified) and only partially on others
(2/13), and a partial patch can panic. Until that is engineered away, treat each attempt as:
verify every dword landed (the script now checks and retries across fresh processes), and **reboot
before retrying** if a run degrades. The single highest-value fix is to reduce the fault rate, e.g. by
gating each write behind a successful probe read of the same page in the same command, or by finding a
single-point root vector (credential-pointer swap) that needs 4 dwords instead of 13.

1. `scripts/patch-dwords.sh write` — writes 13 dwords (52 bytes) of shellcode over `__do_sys_capset`,
   **one dword per process run** via `CHEESE_POKE`. The single-dword path is the one that reliably
   lands; a multi-dword write in one command failed with `EPERM` from KGSL.
2. `call_capset [cmd]` — calls `capset(NULL,NULL)`; the patched handler runs `commit_creds(&init_cred)`,
   so *that process* becomes uid 0; it then `execvp`s the requested command (root shell via `sh`).
3. `scripts/patch-dwords.sh restore` — writes the 13 original dwords back (recorded from the image).

Shellcode layout (13 dwords): `ldr x0, .+8 / b .+12 / <init_cred lo,hi> / ldr x1, .+8 / b .+12 /
<commit_creds lo,hi> / stp x29,x30 / blr x1 / ldp / mov w0,wzr / ret`. The seccomp-clearing stub from
upstream was **omitted on purpose** (adb shell has no seccomp filter; its hardcoded `current->seccomp`
offsets 0x830/0x838 are kernel-specific and could corrupt task_struct here).

Root is per-process and RAM-only: another shell stays uid 2000, and a reboot clears everything.

---

## 5. Deriving the KASLR slide (per boot)

`init_task.cred` (physical `0xaa79c640`) holds a relocated pointer to `init_cred`. Read both dwords
(separate one-read-per-process runs — see the race note below), then:

```
slide = rt_cred - 0xffffffc00a7b0ae0      # must be 2 MB aligned
commit_creds_rt = 0xffffffc008184c94 + slide
```

Cross-check: `init_task.real_cred` (+0x778) must equal `cred`, and the high dword of
`sys_call_table[91]` agreed with the same `0xffffffee` in this boot.

---

## 5b. THE reliability lever: keep the GPU busy (measured)

The SMMU-table update races a **GPU context switch**, so the primitives succeed far more often while the
GPU is actually working. Measured on device with the same 13-dword patch:

| condition | dwords verified |
|---|---|
| GPU idle | **0-2 / 13** |
| GPU busy (`screenrecord --time-limit 900 ... &`) | **11-13 / 13** |

Consequences baked into the tooling:
- `scripts/patch-dwords.sh` starts a synthetic GPU load for **every** mode, including `verify` —
  reads race too, so an idle-GPU "verify" can report garbage and make a good patch look broken.
- The load must cover the whole operation (patch, root call, screenshot, restore), not just the writes.
- A run that cannot complete must be followed by a **reboot**: a partially patched `__do_sys_capset` will
  panic the device the moment anything calls `capset` (observed twice). The scripts auto-restore on
  partial failure, but if the device dies first, reboot is the fix — text is reloaded pristine.

## 5c. Write reliability is PAGE-DEPENDENT (open issue, measured)

Writes do not behave the same on every target page:

| target | result |
|---|---|
| kernel text page `0xa8145000` (`__do_sys_capset`) | writes land: 11-13/13 dwords verified under GPU load |
| `selinux_state` page `0xaaa40000` (`0xaaa40b98`) | write **refused right now**: readback stays `0x01010001` across 12 attempts, with and without load |

Both pages read correctly, and the kernel-image magic still reads at `0xa8000038`, so addresses and the
primitive are fine — it is the *store* to that page that does not take. Note this same write **did** work
earlier in the project (SELinux was successfully flipped to Permissive twice), so the behaviour is
state-dependent rather than a fixed protection.

Diagnostic to run next: write-test several kernel-data addresses (each with a distinctive value, then
restore) to find whether the boundary is per-page, per-region (`.bss` vs `.text`), or time-dependent;
and re-test immediately after a fresh boot. Candidate explanations to rule out: hypervisor stage-2 write
protection over kernel `.bss`, a stray dirty CPU line being written back over our store, or a runtime
re-assert of that specific field.

Consequence: the end-to-end demo (permissive SELinux → patch → root → on-screen proof) is blocked on
this, because it needs the SELinux flip. The text patch itself — the part root actually needs — is
already reliable under GPU load.

## 6. Gotchas that cost real time (read before debugging)

- **The primitive is a RACE, and losing it costs you the context.** The drawstate issues
  `CP_SMMU_TABLE_UPDATE` and then the access; if the access executes before the TTBR0 switch takes
  effect it faults (`GPU PAGE FAULT … TTBR0=<our PA>`). KGSL then throttles:
  `gpu fault threshold exceeded 3 faults in 3000 msecs` → **every later command on that context fails
  with EPERM** ("Can't run payload: Unknown error -1"). Consequence: retry loops *inside one process*
  make things worse. Retry across **fresh processes** and pace attempts (>2 s apart).
  Success rate varies: the same 13-dword patch has landed 13/13 (root verified) and 2/13 on other runs.
- **A partially patched function is dangerous.** With only some dwords written, any `capset` caller can
  execute garbage and panic the kernel — observed as a spontaneous reboot. If a patch run degrades,
  reboot to restore text before doing anything else.
- **A readback that equals the value you wrote is only meaningful if that value differs from the old
  one.** Restoring the *original* bytes "verifies" vacuously (readback == original). For the patch
  (where values differ) verification is real.
- **Marker ≠ completion.** `CP_MEM_TO_MEM` (the result copy) can land *after* the `0x41414141` marker
  write. Poll the **result slot** until it differs from the page fill `0x45454545`, then read. Symptom
  of getting this wrong: a low dword reads correctly while the high dword reads `0x45454545`/garbage.
- **Verify the pushed binary's hash.** A stale on-device `cheese_pa` silently produced `rc=0` with zero
  output and sent me chasing a phantom bug. Always compare sha256 after `adb push`.
- **Upstream bug fixed:** `setup_pagetables(..., uint32_t tt0phys, ...)` truncated physical addresses to
  32 bits — invisible upstream (all their addresses < 4 GB), fatal here (DRAM high bank is 0x800000000+).
- **Memory pressure panics this kernel** (`panic_on_rcu_stall=1`, `log_buf_len=256K` so crash trails are
  lost): a 4 GB or 8 GB spray, or addresses inside mapped DRAM, caused reboots. The known-PA port does
  **no** spray and does not crash.
- **Secure/TZ physical memory is fatal to touch** (reading `0x80000038` rebooted the device). Low bank
  is off-limits; normal DRAM is fine.
- **Never leave an injected page-table entry live** — doing so caused a spontaneous reboot. Read before
  writing so you can restore, and reboot after experiments.
- **`SEGV_MAPERR` on the kernel-VA self-map**: the patched `swapper_pg_dir` entry was verified present in
  DRAM, yet the CPU walk saw an invalid entry. Cache/walk-cache visibility, not a wrong table
  (three independent methods agree on `swapper_pg_dir` = `0xaa472000`). Not needed for root as shipped.
- **Reboot recovery:** the device has no PIN: `adb shell 'input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard'`.

---

## 7. Open paths (unique value each — pick per goal)

1. **Persistence.** Root today is per-process + RAM-only, and the perf leak needs `shell` uid (an app
   likely cannot do it — *unverified*). Options: (a) **tethered re-root on boot** — a host-side service
   that re-applies root when the phone attaches (most realistic); (b) late-load KernelSU-style module
   *while rooted*; (c) verify whether a sandboxed app can reach perf/kgsl at all (SELinux normally denies
   `perf_event` to `untrusted_app`) — this decides whether an app-level root is possible.
2. **Bulk/coherent kernel access.** The self-map would give fast, coherent CPU access to physical memory
   (replacing 4-byte GPU round-trips). Blocked on the walk-visibility question in §6. Unique value:
   large dumps, partition imaging, kernel-module work.
3. **Bootloader / ROM.** Unlock is the only path to custom ROMs (LineageOS 23.2 for AI2202 exists —
   the software is ready). Realistic options: buy a used ZF9 unlocked before the Nov-2023 shutdown;
   watch for ASUS policy reversal; research ABL/EDL (no usable programmer found — the "public" one was
   an HTML page; anti-rollback blocks downgrades and EDL downgrades are documented bricks).
4. **Other unpatched CVEs.** ASUS is EOL, so everything after SPL 2024-07-05 is unpatched — including
   vendor blobs (GPU/DSP/camera/wifi). A public PoC for a *direct* `shell`→uid-0 LPE would skip the whole
   GPU chain. Worth a systematic hunt.
5. **App-reachability audit.** With SELinux permissive, our primitives become reachable from far weaker
   positions. Quantifying "what can an ordinary app do on this build" is both a security answer and a
   root-persistence avenue.
6. **Audio capture (the original goal) — already solved without root:** scrcpy playback capture verified
   (997 Hz tone recovered); on-device equivalent is Android's consent-based AudioPlaybackCapture API.

---

## 8. Layout

```
STATUS.md          running state + receipts
ROADMAP.md         this file (durable handoff)
src/               pa_leak.{c,h} · cheese.c · cheese_pa.c (the workhorse) · call_capset.c
                   host_kallsyms.c (offline symbol resolver) · cheese_scan.c (superseded)
scripts/           root-now.sh · patch-dwords.sh · sweep3.sh (superseded) · verify-backup.sh
tools/             btf_offsets.py (no BTF in this image)
artifacts/         ASUS .145 OTA (SHA-256 verified) · extracted boot/vendor/xbl · kernel.Image
logs/              device logs, screenshots, sweep logs
~/Videos/Zenfone9-backup-NhZOcgfg   media backup (44 files, MD5-verified)
```

**Operating rules:** read before write; restore what you patch; reboot to clear RAM-only state; use the
second Zenfone as the sacrificial unit for anything with panic risk; keep the phone offline.

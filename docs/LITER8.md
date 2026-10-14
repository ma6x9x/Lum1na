# Liter8 kernel patching - static study

Source: `research/Liter8` (clone). iOS 27 RC `24A435` + beta 4 `24A5390f`,
iPhone 11 (n104ap). Tethered CFW boot via `usbliter8` (iBSS/USB). The primary
document is `docs/plans/IOS_27_24A435_RC_PATCHES.md` (1422 lines). This file
records what Lum1na can learn from HOW they manipulate the kernel, statically.
Nothing here was run by Lum1na. No offset from Liter8 is trusted for our SKUs.

## 1. The patch-record architecture (the transferable part)

Every kernel change is a record: (anchor evidence, pre-image original bytes,
replacement bytes, per-build offset). 198 records across 18 fixture plans.
Category counts for beta4 -> RC:

| category | count | meaning |
|---|---|---|
| offset only | 158 | opcode byte-identical, offset moved |
| ORIG CHANGED | 12 | pre-image differs; never transplant the old word |
| REPL CHANGED | 4 | replacement re-encoded per build |
| ORIG+REPL | 4 | both differ |
| identical | 2 | same offset and bytes |

Lessons Lum1naAfterKread must adopt for runtime patching:

- **Pre-image guard.** A patch is refused unless the bytes read at the target
  match the recorded pre-image. This is the same discipline as our probe
  `stopUnlessA14_23F77:` (non-nil = STOP). At runtime post-KRW: kread the
  word, compare, refuse on mismatch, never blind-write.
- **Anchors are strings.** Patch sites are located from unique kernel strings
  (e.g. `AMFI: code signature validation failed`, exactly one occurrence,
  then ADRP+ADD xrefs, then the owning function, then the callee shape).
  Our kread lane can do the same: read strings around a candidate VA to
  confirm identity before writing.
- **Exact-build oracles.** Every record is verified against a fixture for a
  specific build id. Our analog: the LabOff table keyed by
  `kern.osversion`, one row per build, no cross-build transplants
  (T8101 VAs never onto T8020/T8030).
- **Regression pinning.** Beta-4 fixtures stay byte-identical after RC
  support landed; a discriminator tells the two builds apart first. Our
  analog: adding a new SKU row must not perturb existing rows; the tag
  check runs before any lookup.

## 2. BTI: entry vs prologue (iOS 27 kernels)

Apple enabled Branch Target Identification in the RC kernelcache. Most
functions now start `bti c` (0xD503245F) one word BEFORE `pacibsp`:

- beta 4: 0 of 112050 PACIBSP functions have the pad.
- RC 24A435: 87629 of 109000; IDA: 140862 of 190337 functions start BTI C.

Two different addresses for one function:

| name | address | used for |
|---|---|---|
| entry | the `bti c` | BL targets, function pointers, boundary arithmetic |
| prologue | the `pacibsp` | where a two-instruction stub is written |

Conflating them breaks both directions (they observed both). Writing a stub
at the entry destroys the landing pad, which faults on the first indirect
branch IF BTI is enforced. Enforcement lives in SCTLR_EL1.BT0/BT1, which is
programmed by SPTM (not in the kernelcache), so enforcement status is
UNQUANTIFIED, not disproven. Liter8 preserves pads regardless because it is
free (`bti c; <stub>` is correct either way).

Lum1na lesson: any post-KRW stub we ever write on a 24A-era kernel must
target the prologue and preserve the pad, and must treat entry and prologue
as separate resolved addresses.

## 3. What they actually patch (kernel inventory)

Result/return stub pairs: `mov x0, #0` (0x000080d2) or `mov x0, #1`
(0x200080d2) + `ret` (0xc0035fd6); guards NOPed with 0x1f2003d5.

- **AMFI**: trust-cache check replaced by a 5-word function (always proceed);
  launch-constraints result w0=0 + return; post-validation compare polarity
  fix (their Blocker 1: the beta-4 word would have been actively WRONG on
  RC - the tbz/tbz immediate differs, 0x1f080071 -> 0xff070071); dyld
  OOP-JIT policy forced-allow; developer-mode check bypass.
- **Sandbox**: vnode-check-exec/open ADRP targets retargeted to stubs;
  mount-check mount/umount/remount + file-check-mmap result/return pairs
  (x0=0, ret); a NEW 14-word shim written into zeroed space
  (`.vnode-check-open.shim.0-13`) ending in a tail-call - they grow the
  kernel instead of only hollowing it.
- **Panic guards** (order matters: these trip BEFORE anything else works):
  seal-broken, root-snapshot, unencrypted-data-volume,
  rootvp-authentication -> NOP.
- **AKS**: external-method selector7 fully replaced (20 words) so the SEP
  -backed method returns success in a CFW boot; log-call NOPed.
- **SEP**: did-timeout, power-notification, notify-active, panic-check,
  set-power, prng-reseed -> result/return pairs so the kernel does not
  block on SEP interactions the CFW boot cannot answer.
- **Identity**: two 8-byte strings `/RELEASE...` -> `/PATCHE...` - the
  kernel's own osversion string is edited so the build reports patched.
- **Persona**: uid-zero / gid-zero guards NOPed.
- **USB / debugger**: restore-mode check and debugger check stubbed.

## 4. Boot-chain scope (why our runtime lane differs)

Liter8 is BOOT-TIME: iBSS/iBEC/DeviceTree/TXM/kernelcache are patched before
the kernel ever runs, then launchd gets `/usr/lib/lhook.dylib` injected via a
patched service cache, Setup.app class ownership is recovered, and the
APTicket is captured during restore. AMFI is patched before AMFI loads.

Lum1naAfterKread is RUNTIME post-KRW: AMFI and the sandbox are already
initialized. Consequences we must respect:

- We cannot rewrite function pointers AMFI cached at boot.
- Trust-cache additions must go through the runtime trust-cache APIs
  (the Dopamine-style AMFI trustcache lane we already plan), not the
  boot-time amfi.trust-cache stub.
- The panic-guard set is still relevant: seal-broken and root-snapshot
  paths can fire at runtime when we touch snapshot state; the pmap-kwrite
  lane must stay inside what does not trip them.
- The AKS/SEP stubs are boot-only workarounds; at runtime we leave SEP and
  AKS alone entirely (HOLD, and honesty: we do not need them for
  Sileo/Zebra staging).

## 5. Direct mapping to Lum1naAfterKread (the patch checklist)

If Lum1na ever reaches a runtime patch lane, the Liter8 inventory doubles as
the checklist of WHAT needs patching for Procursus-style userland:

1. amfi.launch-constraints (runtime: per-proc csflags, we already do this
   via task-for-pid-style lanes) 
2. sandbox vnode-check-open family (runtime: per-process sandbox escape is
   what we do instead - we never patch the kernel sandbox at runtime)
3. panic guards (runtime: avoid tripping, do not patch)
4. identity string (runtime: cosmetic, skip)
5. trust-cache (runtime: ADD to trust cache, not stub the check)

Ordering lesson from their Blocker 1: a patch that is right for one build
can be actively wrong on the next; pre-image guards are not bureaucracy,
they are what prevents a live kernel corruption. This is exactly the class
of bug the socket_usecount=0x254 ladder fill fixed for us (2026-10-14).
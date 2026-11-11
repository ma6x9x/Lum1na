# External intel — airlift / varik / AltDaemon / Nyxian (2026-10-15)

Four outside sources mined for Beta-1, the 26.5 port, and the bounty loop.
Nothing here changes LabOff, the board, or any honesty gate. Licenses
noted per source; no code copied into this repo yet.

## 1. 0xjohnnydev/airlift — AirTraffic/ATAirlock escape (MIT, 410★)

**What it is:** a **paired-Mac** file read/write primitive for iOS 27.0
(tested 24A435 RC / 24A437 final). Runs from the Mac over Wi-Fi/USB —
**no iOS app required**. Host chain:
`MobileDevice → AirTrafficHost → com.apple.streaming_zip_conduit →
com.apple.afc → com.apple.atc / AirTrafficDevice → Books sync client →
ATLegacyAssetLink → ATAirlock → NSFileManager`.

**The bug (classic double-move path validation):**
`-[ATAirlock processCompletedAsset:]`
- source = `/var/mobile/Media/Airlock/Book/` + `asset.identifier` —
  the Books "Persistent ID" reaches `identifier` with **no path
  validation** (`..` accepted).
- destination = `/var/mobile/Media/` + `FileComplete.AssetPath`,
  `stringByStandardizingPath`, then only an `hasPrefix:@"/var/mobile/Media/"`
  **string check** — symlink ancestors not resolved.
- Move 1 relocates a contained symlink under Media; move 2 follows it and
  writes the payload outside Media.

**Verified write scope:** `/var/mobile/**` (Documents, Library,
Preferences, Caches, SpringBoard, SMS, Safari, Containers/Data/Application,
Containers/Shared/AppGroup, /var/tmp). Reads are indirect (move into
Media → AFC read → move back). **MobileGestalt plist: NO.**

**Beta-1 value:** on a paired Mac this is a **side-loaded file plant
into any app container + mobile dirs** — staging channel for persistence
files, logs pull (Safari/SMS), and app-data seeding on the hunt device
without any kernel work. **KRW value: none** (mobile-domain fs only).

**OPEN TASK:** the ATAirlock class predates 27.0 — check
`-[ATAirlock processCompletedAsset:]` identifier validation on **23F77**
(26.5 hunt) dyld cache. If the unchecked-identifier shape is present,
airlift's host tool (MIT) plausibly works on the hunt device unchanged.
That is a Beta-1 distribution/staging channel, not an exploit door.
Do NOT claim it works on 26.5 until run.

## 2. varik.dev — "Getting into Apple Security Bounty" (write-up)

Varik Matevosyan (@D4RK7ET): first Apple CVE after ~2 months
(CVE-2026-65395 ImageIO OOB write, $1k shared-with-P0 credit; Calendar
vCalendar 1.0 heap OOB write acknowledgement). Actionable for our skill:

- **Target Flags** (new Apple program): capture register control / PC
  control / TCC flags in the PoC → higher payout + faster triage. Every
  report card should list captured flags.
- **Reachability rule:** verify the bug from a **first-party shipping
  binary** (QuickLook, Calendar, Safari…). Without reachability proof
  Apple may reject. Attach crash `.ips` + a demo video.
- **Report-as-crash, then maximize:** file the crash first, use triage
  time to push escalation (control-flow / flag capture) and add data.
- **macOS carry-over:** kernels/frameworks are near-identical — audit on
  macOS, confirm on iOS. SIP debug restrictions OFF for lldb on system
  processes.
- **Tooling:** `ipsw` CLI (agent-drivable), Ghidra + **ghidra-rpc**,
  IDA + PacXplorer / ida_kernelcache / FunctionInliner (Cellebrite),
  **vphone-cli** (virtual jb iPhone for harnesses), XNUSP kernel CLI lab.
- **IOKit methodology (matches our probe philosophy):** build UC calls
  **manually** — high-level wrappers do the sanitization you want to skip.
- **Root-daemons:** sandbox-profile `mach-lookup` check first, then
  enumerate handlers → logic bugs (missing authz) or parse memory bugs;
  daemons double as TCC bypass / sandbox escape.
- **Prompting ops:** context-heavy prompts; beware skeptical auto-memory
  (agent stops doing deep analysis); cross-agent peer discussion
  (leader/member, TEAM.md surface ownership, send evidence not pointers).

## 3. AltDaemon — jb-side app-signing persistence (ecosystem tool)

ichitaso page is Cloudflare-gated; ecosystem repos instead:
`emp0ry/AltDaemonModern` (AGPL-3.0, rootless/Dopamine, anisette v3),
plus iOS 17 roothide crash-fix forks. Function: keeps AltStore alive on a
jailbroken device and refreshes/re-signs sideloaded apps **without a Mac**.

**Value:** distribution/persistence for **jailbroken rigs only**
(12 mini 17.3, iPhone 11 18.6.2-Dopamine): keeps the Lum1na IPA signed
indefinitely on-device. Hunt 26.5 is not jailbroken — N/A there. No code
to copy; an operational install on the rigs at most.

## 4. Nyxian — jailed on-device IDE + Procursus Jailed (senumy listing)

On-device native IDE with a "userspace microkernel", iOS 18–27+ (claims
27.2b2 testing), works **on stock iOS** via developer signing;
Procursus Jailed runs Sileo-managed DEBs inside its container. Does NOT
work inside LiveContainer.

**Value:** (a) **on-device iteration** — compile/run probe-shaped native
code on the hunt device without Mac+CI round-trips; (b) **signing
persistence** — its cert-import flow is another keep-alive vector for the
7-day signature on stock devices; (c) **distribution** — Beta 1 could
ship as an installable alongside it. It is jailed: no kernel surface, no
sandbox escape — a harness, not a door. Closed listing page; treat
compatibility claims as unverified until installed.

## Money path (varik-derived, folded into the ios-xnu-hunt skill)

1. Keep Lum1na private (this repo + rig devices) — it's our validator,
   never the deliverable.
2. Audit on macOS with the agent (frameworks first — fastest CVEs),
   confirm reachability from a first-party binary, grab `.ips` + video.
3. Score with the rubric; drop <12 same day. File crash early; maximize
   to Target Flags during triage.
4. Kernel/kext lane stays pre-gate honest: `hasKread` per SKU first
   (rig: YES via cs2core; hunt 26.5: NO — four live leak/reach doors
   from CASESTUDIES.md are the working set).


## ios27-jb-tracker (iMaxTomas) — borrowed 2026-11-01 (clone: jb-sources/)

The 32-claim fact-check DB for the Calif/Chollima iOS 27.0.1 demo (Hexacon
2026) + the iPhone Duo release-day pop. NO tools in the repo — documentation
only. Borrowed rows (EN summary):

- **V17 (HIGH, verified) = OUR LEAD**: MMdAS independently reproduced
  **CVE-2026-112705** — VideoToolbox session with **NumberOfTemporalLayers
  = 16463** (16462 survives) → first encode → AppleAVE2 kernel OOB WRITE
  panic at +0xDA78, far=0x59, x0=0x100000059 (N=16464 → 0x100000001-class);
  fixed in 27.2 (24B119) with a -12900 pre-check. Repo:
  MchinaMd57764/AVETemporalPoC-CVE-2026-112705. **Our tap = P142** (the
  knob battery; likely-live on 23F77's AVE2 913.43-class, the 17's 24A435
  = the sibling class).
- V7/V8 (medium/high): an INDEPENDENT SPTM bypass works ≤27.0.1 (patched
  27.2b3, unverified) — the community's version of our wall law:
  ClearSword/DarkSword kernel bugs cover ≤26.0.1 only; >26.0.1 needs a new
  kernel bug = the lab's standing verdict, third-party pinned.
- O1 (high): Dopamine 3.0 = A12/A13 only, ≤26.0.1; A14/A15 have ZERO on any
  26.x — the A14 cap = **iOS 17.3.1** = explains our mini's OS exactly
  (21-D50 = ON the cap).
- V5: usbliter8 = Paradigm Shift's 2026-06-18 disclosure, A12/A13+ S4/S5
  SecureROM, unpatchable-via-OS, physical — matches our rig memory.
- V15/V20: 27.0.1 still signing as of 10-24 ("countdown"); the community
  expects Calif's write-up after 27.1 stops signing; the bottleneck =
  disclosure timing, not tech.
- V19 (medium): Calif's bare SHA-256 hash commitment (unverified meaning).
- V18 (low): ikotas00's 27.2 root demo = image-only, unverified.

## Ketamine/GestaltEdit MobileGestalt lane (2026-11-10)
- withered.live/ketamine 2.1b1: MobileGestalt editing + customization are
  carriers of the **worse_query** class (forcequitOS; bad_query = older,
  0xjohnnydev AirLift = the second write path). Gate table by BUILD not device:
  **26.0–26.6.2 ✗ | 26.7–26.7.2 customization ✓ / MobileGestalt ✗ |
  27.0 stable, 27.0.1, 27.1 ✓✓ (worse_query) | 27.2 stable ✓✓ | 27.3+ ✗**.
- github.com/frs0n/GestaltEdit (iOS 26+): same class ("FilzaSlop/worse_query
  file access research"); writes com.apple.MobileGestalt.plist on-device,
  respring to apply, warns restore may be needed on bad values.
- **Fleet cross-validation (P160 = the same worse_query/mcm class):**
  - 12/23F77 (26.5): table says ✗ — matches our P160 open=0 on the 12; the
    12's read receipts came from P116's NOFOLLOW bug, a DIFFERENT hole.
  - iPad8,7/23H30 (26.7.1): customization ✓ — matches p160 v2c class-7 read
    receipts; the table also predicts **MobileGestalt editing ✗ here**
    (consistent with our write=EPERM).
  - 17/24A435 (27.0 stable): both ✓ — one p160 v2e tap on the 17 should now
    give the class-7 read the iPad gets. NOT yet replicated on the 17.
- **17 "better target" verdict:** for the write/customization lane yes
  (27.0 stable is inside the worse_query window; 26.7.1's MG-edit door is
  shut per the table), for KRW no (SPTM/MIE, T8150 ident-only, data-only
  post-KRW law). The 12 remains the KRW hunt. **Do not let the 17
  auto-update past 27.2 — 27.3+ kills the class.**
- Write-leg experiment the table enables: P116 rw is /var/mobile-restricted,
  which covers `/var/mobile/Library/Caches/com.apple.MobileGestalt.plist`.
  Law applied: read the live plist first (p116_path), write to a COPY
  (e.g. `...MobileGestalt.lum1na_copy.plist`) via p116_rw_path — never the
  live MG cache.

## filza27.2 + ipadn vendor pull (2026-11-11, ios-xnu-hunt/vendor_intel/*)
- **git.jbjflab.top/admin/filza27.2 v27.2.0** ("worse_query build", iOS 26.0–27.2):
  Filza fork over forcequitOS/worse_query + 0xjohnnydev/FilzaSlop, two
  side-by-side builds (public = browser; develop = a-Shell terminal,
  apt/dpkg, libssh root/mobile SSH, mount, Erosion WebKit respring).
  **It is KRW-based**: `sandbox_escape.m` walks proc_ro→ucred→cr_label→
  sandbox→ext_set, rewrites every extension path to "/" + class to
  `app-sandbox.read-write`, fills all 16 hash slots, then swaps launchd's
  ucred into its own proc at self_proc+0x10 for uid 0. Offsets from
  CrazyMind90's 18.3_sandbox root.m; KRW provider = the vendored
  `kexploit/kexploit_opa334` ("darksword-kexploit-fun", seo) — **the
  CS2/socket lane** (inp_list/icmp6filt/ipi_zone/so_usecount — the lab's
  own ClearSword family), 26.x offset-derivation patterns included
  (thread t_tro/upcb/ctid/options hex rules), tested iPhone12,8/13,1/15,2/
  iPad7,11/**14,6 iOS 26.0**.
  **MCM proof rows (MHA-*, 24A5390f archive) — the P160-EPERM answer:**
  classes 2 app / 4 ext / 6 VPN / 7 groups / 10 service / 12 system /
  13 system-GROUP / 15 app-managed; lease flags 0x900000000, enumerate
  0x100000000, part-write 0x8100000000. Class-12 `com.apple.geod` rides
  ContainerManagerCommon's built-in lookup-bypass list and part-domain
  traversal reaches the MobileGestalt Caches (275-byte RW extension proof).
- **mengangs/ipadn** (GPL-2.0): App Store own-app installer — native on-device
  install via developer-mode pairing (iOS 27+) or jkcoxson/idevice_pair
  remote-pairing (17.4–26) + LocalDevVPN. Deployment plumbing, no exploits.
- **Adoption status:** P164 = our own translation of the MCM census/probe
  rows (read-only). Queued: p116 v4 fsgetpath inode enumeration (pathleak
  rewrite — GPL-3, credit Taj C/forcequitOS), P165 post-KRW sandbox-unpatch
  + launchd-ucred uid0 gated on hasKread (offsets cross-checked against our
  LabKernelOffsets DB: proc_ro_ucred 0x28, ucred_cr_label 0x78 — matches).
- Licenses: filza27.2 repo ships no LICENSE (our lab's server); FilzaSlop
  base is Filza-derived — keep attribution, no wholesale vendoring into
  the public repo. worse_query/pathleak = GPL family; technique credited.

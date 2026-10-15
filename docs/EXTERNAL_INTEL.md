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

**Beta-1 value:** on a paired Mac this is a **jailbreak-free file plant
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
27.2b2 testing), works **without jailbreak** via developer signing;
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

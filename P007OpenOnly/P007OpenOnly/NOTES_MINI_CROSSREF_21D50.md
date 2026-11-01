# NOTES — the 12-MINI CROSS-REF BATCH (21-D50 / 17.3, Dopamine) — 2026-10-31

The user's question of the night: *"the 2c2s we've seen everywhere can be
bypassed because even on the jailbroken device we get similar results —
the device should be capable, right?"*

## The verdict (honest, split in two)

**Right about what it proves.** p138 on the mini = IDENTICAL to the 12 and
the 17 (`mach_vm_map kr=0x1d`, all six ops `2c2`, op-2 oracle `2c2` +
gate `0`). A device with a full kernel-access lane available (Dopamine
libkrw, kbase `0xfffffff023060000` from the 2026-10-23 FKT workbench run)
returns the same op-channel walls through OUR app. This KILLS the
"23-F77-only hardware wall" theory for the op-channel class: the wall is a
property of the app's access path, not of the device or the train.

**Wrong about the mechanism.** (a) The mini does not raise our app's trust:
p117 on the mini shows the SAME all-NIL entitlement echo (only
`get-task-allow` survives). The free-profile stripper follows the app
signature, not the host — being on a jb phone does not give our free-signed
binary platform keys. (b) So "bypass" is not entitlement work; on the mini
the real bypass is INSTRUMENTATION: we no longer have to ask the port and
guess — we READ the object the port points at. That is what p140 does.

## What tonight's mini batch actually landed

- **p138 mini** — Route-D cross-train closure (identical wall shape on three
  devices + a jb host): the op census question is reopened ONLY as a
  kernel-read question; the 23F77 port-path decode answer on the mini:
  the object's fields ARE readable (p140), ops gated vs ops absent
  = decidable tonight.
- **p117 mini** — all-NIL even on the jb host: the entitlement-vector
  experiment class is VOID via app re-signing on every fleet device. The
  remaining trust-differential = a ROOT-spawned helper (Dopamine grants
  platform trust to jb processes) — next-session scope, needs ssh.
- **p084 recipe on the mini** — PHASE A/B complete mechanically
  (65,537/65,537 maps OK; single unmap `kr=0`) but PHASE C: 178 fresh L3
  pages, `faults=0 unchanged=96` ×2, watch 60 s clean — the free did not
  fire or quarantine held. SPTM-era note applies with MORE force: T8101
  SPTM status is unpinned, and the recipe's pt_desc arithmetic is a
  fixed-train shape. The mini can instrument it live next time (read the
  pt_desc u16 refcount DURING phase A via lane kread — if it does not
  climb/wrap, the recipe is mis-fit for 21-D50, not mistimed).
- **p073 mini** — engine ran, miss-adjacency, `descForged=0`; the one
  RECEIPT that DID land: forged-type send `kr=0` ACCEPTED + recv
  `desc_count=1` (the desc door's translator fires on 21-D50).
- **p139 mini** — collated (rows=4; aio family + oracle row; band check).
- **p118 mini** — offsets.json DERIVE wrote the A14-21D50 ladder row;
  status still DERIVED, not read-verified.

## The LightSword question (user: "our port logic could be wrong")

Mac-side byte-verification tonight against `upstream/Dopamine/BaseBin/
libjailbreak/src/info.c` and our og `ClearSwordCore/common.h`:

| off | ours (A14-21D50) | og source | verdict |
|---|---|---|---|
| socket.usecount | `0x24C` | info.c darwin<23.4 branch = `0x24C` | SAME |
| inpcb.icmp6filt | `0x148` | `CS2_KOFF_inpcb_icmp6filt 0x148` | SAME |
| inpcb.inp_socket | `0x40` | `CS2_KOFF_inpcb_socket 0x40` | SAME |

So the offsets are NOT the mini-miss cause — og common.h literally pulls
`LabOff()`, the same table. Suspects that REMAIN (ordered):
1. **the gencnt law**: og `poc.c` reads `inp_gencnt` from
   `__proc_info(CS2_PROC_INFO_CALL_PIDFILEPORTSOCKETINFO …)` blob **+0x110**
   (with the author's own "may need to check this offset for various
   versions" caveat). Our LightSword calib v10 scans a DIFFERENT law
   (inpcb+0x78 per LightSword.m:16). Reconcile v10's classification
   against poc.c's driver loop before judging the mini.
2. **the spray budget**: og budget constant = `CS2_MAX_SOCKETS_COUNT 0x5800`
   (~22.5k); the v10 run ended at **1,230,336 sockets** — a categorically
   different zone state (50× over-spray changes allocation/reuse patterns).
   og's mlock count = `CS2_MAX_LOCKED_SURFACES 8` (v10 locked 2).
3. `H: iters=3000 wFail=3000 hits=3000` — decode v10's H semantics against
   poc.c's loop before reading this as pass/fail.

-> Next on the mini: run the og poc.c driver (the "og clearsword" the user
says works) and OUR calib in the SAME boot and diff the intermediate laws
(gencnt source, socket count at sweep time, mlock census).

## FKT workbench receipt (2026-10-23, on this rig)
`dlopen libjailbreak` + direct `libkrw/libkrw-dopamine.dylib` both load;
`kbase() = 0xfffffff023060000`; helpers incl. proc_find/vread reachable.
The FIELD# twins pinned there and honored everywhere: SysMemory MD
+0x90 (23F77) vs **+0x80 (21-D50)**; p010 word1 queue+0x558 (23F77) vs
**+0x550 (21-D50)**.

## Honesty
Nothing tonight flips `hasKread` on the hunt-12 (23F77). The mini's
receipt is its own device's gate, landed only after the lane is live. All
mini numbers stay twin-CLASS/FIELD; `21-D50 = per-segment decode law`
(memory) and VAs never paste.

## THE ROOT-LANE RUN (frida + ssh, 2026-10-31 night) — instrument stack live

Mac-side stack now proven: `iproxy <macport> 22` + keyless `ssh root@localhost
-p <macport>`; frida 17.25 on BOTH ends; the app launches via frida
`dev.spawn("ma6x9x.P007OpenOnly.V467U8LP46")`. Scripting laws (paid for):
frida 17 = `Module.getGlobalExportByName` static is GONE from... (`sym(n)`
shim: GlobalExportByName first, getExportByName(null) fallback);
`mach_task_self` is a MACRO — resolve `mach_task_self_` and readU32;
`kCFAllocatorDefault`/other const-pointers must READ their value
(`.readPointer()`), only the callbacks struct passes as address;
SecTaskCopyValueForEntitlement takes CFStringRef (never char*).

### Laws landed tonight
1. **THE ROOT RECEIPT**: libkrw-dopamine from a frida-spawned uid-0
   process — `krw_initializer rv=0`, `kbase=0xfffffff016238000`
   (KASLR re-slid from the 10-23 FKT run's 0xfffffff023060000),
   **kread32(kbase)=0xfeedfacf PASS**. The mini's kernel-receipt
   instrument = reproducible from the Mac tonight.
2. **uid 0 DOES NOT lift the entitlement stripping** — the frida-root
   process echoes p117 IDENTICALLY (all NULL; `platform-application`
   returns typeid-21 OTHER, not NULL — a present-but-unmapped shape to
   decode; the app's in-app p117 run prints the same NULL rows).
   Capability on this rig = the TRUST CACHE / CS identity of the SPawner,
   not the uid, not the host. The p117 verdict extends: our app's
   entitlements would stay stripped even if the device were jb'd (the
   hunt-12 question answered in miniature).
3. **libkrw loads + initializes INSIDE the free-signed app** (rv=0 — the
   dlopen survives the sandbox) but kbase()/kread return nothing: the
   jbserver mach-lookup dies under the app's sandbox profile. Honest
   wall NAMED (mach-lookup class), not yet broken.
4. `IOSurfaceCreate` works in-app under frida (surface ref back);
   `IOSurfaceCreateMachPort` access-violates in the frida-spawned context
   (AV tail 0x...f001300 identical across 3 runs = one fixed field read,
   isolatable). Normal-launch comparison (user opens app, attach frida,
   tap p138/p137) = the pending isolation.

### Next (ordered)
- User opens the app normally; attach frida + user taps p138 → compare
  vs the frida-spawned AV (isolates the spawn-suspend law).
- The p140 IPA tap on the mini (own receipt row + object read WITHOUT
  frida).
- If IOSurfaceCreateMachPort AV persists in-app via frida: the locator
  fallback = kobject on ANY port class the app holds (p090's ipc rows +
  IOConnect ports) — the FIELD# law needs a locator per class, not per
  object.
- LightSword: same-boot og-poc.c vs calib-v10 A/B (the gencnt law
  +0x110 caveat; the 0x5800 budget).


### The IOSurfaceRoot rows (user's nudge — tested from the ROOT host)
IOKit route from root, IOSurfaceRoot service = FOUND (class decoded
`IOSurfaceRoot`):
- `IOServiceOpen` type 0 → **kr=0xe00002e2 (EXCLUSIVE ACCESS)** — the
  root UC type-0 slot is exclusively held on this boot (the graphics
  server's client); NO in-app comparison yet on the mini.
- types 1/2 → 0xe00002c7 (resource conflict).
- Framework `IOSurfaceCreate` from root = 0x0 (the framework's client
  setup does not complete in the CLI context).
Conclusion so far: the ROOT host cannot open the surface lanes itself;
the p138 census therefore still needs the APP host for creation +
ROOT lane only for reads. p140's in-app tap (locator + lane reads,
no frida) = the remaining path for tonight's object read.

### The future-version kext scout (first pass, Mac-side)
- `kext_inventory_23F77.txt` = 218 load rows; 24A437 = 301 fileset
  entries. Smallest 25 ranked (relative order). Candidates that sit in
  BOTH inventories and are tiny: **AKSAnalytics** (the ANE family's
  sibling — our existing lane family), AOPTouchKext, ASIOKit, AUC,
  AppleA7IOP, AppleALSColorSensor, AppleAOPAudio, AppleARMIISAudio,
  AppleARMPMU, AppleARMPlatform, AppleARMWatchdogTimer, AppleAVD,
  AppleAVE2, AppleActuatorDriver, AppleAstrisGpioProbe (new class,
  GPIO-probe-shaped), AGXFirmwareKextRTBuddy64.
- New on 24A437 only (G18P generation = 17-device): AOPaudio2,
  AppleAOP2, AFKHIDTBDevice, AGXG18P.
- Method for the next scouting round: for each candidate, decode the
  UC sMethods table + any entitlement gates in the 23F77 kernelcache
  (the 26.5-relevant side), and check the p018-style root-UC lane.


## THE AKS-ANALYTICS KEXT DECODE + the fleet entitlement-gate map (23F77)

User opened AKSAnalytics (23F77 kext) in the Ghidra program. Decoded:

- AKSAnalytics = the **DataProtection analytics kext** (not ANE): DPSerializedEvent,
  kauth-vnode hooks, dataprotect policy config; service class = `AKSKernelServices`,
  UC = `AKSAnalyticsUserClient` (gate `com.apple.keystore.analytics` — VOID for
  free-profile, p117 law).
- `sendDataToUser` = the dataQueue CONSUMER path ([self+0xe8] dataQueue,
  [+0xe0] client conn, [+0xf0] bit0 enable flag; send = vt+0x90 has-space gate)
  — bounded, no OOB shape.
- `dataprotect_internal_entitlements` = a PEBL sysctl config flag (0x8080b20
  reads five dataprotect_policy_* boot/config switches) — a kernel-side config,
  not a user hook.

### THE ENTITLEMENT-GATE CENSUS (new fleet law, 23F77 kernelcache-wide)
Pattern: every gate-carrying UC carries the string `IOUserClientEntitlements`
followed by its key list — **20 UCs total on 23F77**:
  IOHDIX(root-removable?), AKSAnalytics(keystore.analytics),
  AppleARMSPIDevice(spi.device.user-access), VT-hw-video-decoder(videotoolbox.
  hardwarevideodecoder), AFKSharedMemory(afk.shmem-user), AppleGPIO
  (applegpio-access), AHS.Power(ahs.poweruserclientaccess), JPEGDriver(2 keys),
  ApplePMGR(private.ApplePMGRUserClient.access), AppleSMC-ACAM, GNSS-SPU(2),
  GasGauge(private.gasgauge-update), AppleSmartIO2, **Stockholm/hammerfest
  (nfc.disableentitlements flag + com.apple.stockholm.kext.entitlement +
  com.apple.hammerfest.kext.entitlement)**, IOPort(iokit.IOPortFamily),
  PSVR2-FastPath, HID-fastpath(2), **IOSurfaceRootUserClient = only 4 keys
  (iosurfaceinfo / private.gpu-restricted / developer.gpu-restricted /
  IOSurface.protected-access)**, TimeSync(timesync.clocksync).

### The laws this census pins
- **H11ANEIn's row carries NO key after IOUserClientEntitlements** = the ANE
  user client has NO gate key in this mechanism = statically explains why the
  ANE lanes open at type 1/4 on every device (p109 precedent). The ANE family
  = the no-wall lane; the 2c7/2e2 walls we see = OTHER mechanisms (procIdx, program
  policy).
- IOSurfaceRootUserClient's 4 keys = info/protected-access gates, NOT an open
  gate (p018 opened fine) — surface lanes stay open.
- Everything else on the map = VOID for our signature (keys stripped).
  The kext-scouting grid = decode each of the 20 rows' KEY-VOID status first;
  only key-void or non-gated kexts remain as primitive candidates.


### 21-D50 cross-train census (the mini's cache, same scan)
21-D50 rows = **13** (vs 23F77's **20**). ABSENT on 21-D50: AKSAnalytics,
AppleGPIO, ApplePMGR, PSVR2-fastpath, Stockholm/hammerfest, AFK-renamed
(afk.user on 21-D50 vs afk.shmem-user on 23F77), quadSPI (SPI variant
naming changed), HID-fastpath renamed (FastPathHasEntitlement only).
PRESENT on both: VT-hw-video-decoder (SAME key both trains), JPEGDriver,
GasGauge, SmartIO2, IOPort, TimeSync, SPU.

LAW (cross-train): the VT-hw-decoder key = train-stable; Stockholm's
gates + PMGR's gate + GPIO's gate = POST-17.3 additions = **newer walls**.
ANE = key-void on BOTH trains (the no-gate law carries). The primitive-
candidate grid = the key-void set + the non-gated UC space, verified per
train first (the 21-D50-first proof rule — user's directive).


## AMFI opened (23F77 the user's Ghidra program) — the workaround map

Static shape: AMFI's own UC (AppleMobileFileIntegrityUserClient) = 5 gated
selectors (can-set-denylist / can-load-trust-cache / can-load-cdhash /
developer-mode-control / garbage-collect-profiles) — all platform-only.
The execve hook chain + the OSEntitlements API family (getOSEntitlements /
copyOSEntitlements / getOSEntitlementsFromProcSecure, config node
iokit.OSEntitlements) = the kernel-side ENT SOURCE the p117 law reflects.

### The workaround verdict (honest, in-scope)
1. Entitlement stripping = at the AMFI-PROFILE stage (our signature), not
   in-process: nothing an app can flip from inside. Confirmed cross-device
   AND cross-host (root-uid lift = NULL rows, tonight's frida receipt).
2. The per-UC gates consult the CLIENT's AMFI entitlement view per KEY:
   a missing key = refusal at open/selector. So the in-scope workaround =
   pick lanes whose gate key-list is VOID:
   - ANE family = key-void BOTH trains (tonight's census row) — the
     opened-at-1/4 law, statically explained.
   - IOSurfaceRootUC = open (its 4 keys gate info/protected-access SURFACES,
     not the connect; 21-D50 does not even carry the row).
3. The check CHAIN for the record: IOServiceOpen → IOUserClient::start →
   the UC's declared IOUserClientEntitlements key list vs the client's
   AMFI entitlement dict → refusal (2c2/2e2-family), which the app
   sandbox compounds for the jbserver lookup (the mini's live wall).
4. Mini v2 plan: 21-D50 AMFI static decode (the mini's cache is on disk:
   kernels/21D50/21D50__iPhone13,1/kernelcache.release.iPhone13,1) →
   locate getOSEntitlementsFromProcSecure + the gOSDict/ent table →
   via the ROOT lane kcall = the kernel-side ENT dump for any pid
   (our app vs a jb tweak vs SpringBoard) = the p117 law's ground truth.


## IOUSBDeviceFamily opened (23F77 kext via the bridge) — the device-side USB hunt

Identity: kext band __text 0x98ad310-0x98d530f, cstrings 0x77a0e58+;
the mini's cache carries the same family (AppleT7000USBOTGDevice rows) =
both trains. It services the DEVICE-mode USB (the phone as a USB device =
every afcclient/iproxy session) — matches the lab's USB-hang corpus.

- **gate census: ZERO IOUserClientEntitlements rows in the whole kext band
  (23F77)** and no USB row in the 21-D50 census either = the USB device
  Family = **KEY-VOID / ungated UC space** (the gold the user predicted).
- **IOUSBDeviceInterfaceUserClient::start = FUN_98bcb60**: NO entitlement
  check at all — provider + WorkLoop + _commandGate + _classCommandTimer
  (FUN_98bc6d0). A TIMER-DRIVEN polling UC = the lock/wait shape behind
  the hang symptoms.
- **handleUserlandCommand = FUN_98bec80**: the userland-command
  multiplexer (visible branch = SetDebugFlag; flag store at [self+0x1dc],
  commands carry vt-multiplexed subops; string = the dispatch log tag;
  zero direct xrefs = vtable-dispatched = an index-reachable UC method).
- The class family: IOUSBDeviceInterface (the service), IOUSBDevicePipe,
  IOUSBDeviceControlRequest (+ its debug variant), IOUSBDeviceLib plugin
  (the IOCFPlugIn the userspace side loads).
- Ent keys touching USB in the cache: com.apple.developer.driverkit.
  transport.usb (DriverKit-side, not app-relevant), com.apple.private.
  usbdevice.setdescription, com.apple.usb.{authentication,externaldevice.,
  hub.} — none = an IOUserClientEntitlements row for the FAMILY.

### Reachability question (the next oracle)
IOServiceMatching("IOUSBDeviceInterface") + IOServiceOpen type 0 from an
app = UNKNOWN on both trains (device-mode nubs are often
controller-owner-only; the answer = one bounded census tap). RISK NOTE:
any USB wedge during the probe = the lab link itself (one open + bounded
sel sweep; run on a device with no active afcclient session, or accept a
possible reconnect).
### The hang-panic cross-ref (do on the next corpus pass)
The lab's USB hangs during earlier sessions decode against this kext's
_commandGate/_classCommandTimer pair (the timer-driven UC). When the
hang .ips class gets triaged, match writer-PC/thread against 0x98bc6d0
(the timer) and 0x98bec80 (the command mux) FIRST.


## THE IOSURFacEROOT/USB REACHABILITY ORACLE (the user's pick) — mini-first

Run twice per host, mini 21-D50 (frida root lane + the app host):

- `"IOUSBDeviceInterface"` = **SERVICE VISIBLE from the app** (uid 501,
  sandboxed: svc=0x1803 class=IOUSBDeviceInterface decoded) — the family's
  service match + get-matching-service = PERMITTED in-app.
- **IOServiceOpen type 0 AND type 1 = kr=0xe00002e2 (EXCLUSIVE ACCESS) from
  BOTH hosts** — sandbox-independent, uid-independent. A 60-open async
  hammer from root = 60×2e2 (no land); a second sweep = all 2e2. NO open
  landed during any window (no replug was performed — the run never saw a
  re-enumeration).
- The IOSurfaceRoot row (same instrument, root) = type-0 2e2 + 1/2 2c7 = the
  SAME exclusivity shape — a UC-class owner-held law, not a lane law.

### Honest verdict for the tethered-path idea
The device-mode UC family is KEY-VOID (no entitlement walls) and the
service matches in-app, but the OPEN is owner-held (2e2) — the tethered
path is NOT unlocked by this tonight. The remaining levers:
1. **who owns it**: the UCD's exclusivity shape = decode in Ghidra (the
   kext's 2e2 throw sites + the owner process), or kread the UC's owning
   task/port via the root lane once the kobject locator's lane isolation
   lands (p140 tap).
2. **IOUSBDeviceControlRequest** = the OTHER door in the family (the
   vendor/command-request class; service = the class itself) — the same
   oracle run against it.
3. A real re-enumeration window was NEVER tested (the user replugged
   nothing yet) — the hammer + replug A/B = still possible.
4. The 26.5 (23F77) in-app oracle = the IPA tap (the p018 law runs there
   TODAY for IOSurfaceRoot; the USB row = the same tap's neighbor).


## p018 v3 receipts (A19 Pro = the 17 + A14 = the mini; the hunt-12 run still owed)

- sel36 {id,0,0x1000} = SUCCESS on both (sout send right, refs=1).
- **mach_port_kobject on the sout: type=0x1b, kr=0, addr=0** — the locator
  returns the TYPE but HIDES the kaddr on modern iOS = the kaddr source
  stays the kread/kcall class (the p140 plan holds; the locator-only hop
  does NOT ship the object address).
- AppleJPEGDriver OPENS in-app on both (conn=0xf133/0x6523); the
  dest=surfaceID encode = `0xe00002cc` ×5 on both = the JPEG-dest CANNOT-
  LOCK wall = **train-stable** (17 and mini, same wall).
- GetBaseAddress = 0x0 before AND after IOSurfaceLock (kr=0) on both:
  the surface stays kernel-only for our app even locked.
- **IOSurfaceRoot IOServiceOpen = SUCCESS in-app on BOTH** (conn=0x f463/
  0xbd03) — confirms the root-2e2 row = a context law (the frida-root CLI
  sleep lacks something the GUI app has), NOT a fleet wall.
- The root-UC method sweep sels 0-31, scIn 0/1(id) = ALL silent 2c2
  (both hosts) = the grammar wrong per-method (blind = dead), matching
  the K2K/contract law. The IOSurfaceRootUC's sMethods decode = the
  Ghidra static step (IOSurface kext in the 23F77 cache) BEFORE any
  further in-app sweeps.
- p018 verdict rows: "WALL STANDS all attempts" = the IOSurfaceID-lane
  stays closed on BOTH devices.


## The cs2 ret=5 differential (12-mini WORKS / newer dies) — first decode

The user's frame: cs2 flips kread/kwrite on the mini but on the newer
devices the engine "keeps going" and ends ret=5, Unable to find kaddr.

Decoded chain (Exploit/ClearSwordCore/krw.c + socket.c + LightSword.m):
1. `cs2_set_target_kaddr` (krw.c): the kwrite window = setsockopt
   ICMP6_FILTER over the control socket; invalid-kaddr = the window
   drifted (log-first-3 law in place).
2. The DISCOVERY = `cs2_find_and_corrupt` (socket.c:87): OOB-reads the
   mapped window, then `memmem(executable_name)` over the zone bytes,
   then REVERSE-memmem back to `corrupted_filter_marker =
   0x0000ffffffffffff` (= icmp6filt NULL + chksum -1 + hops -1), then
   `pcb_start = filter_off − (icmp6filt + 8)`. Source comment:
   "assume inpcb base = the 0x400-round-down, that's not true for < 17"
   = the scan is LAYOUT-dependent (17.x-era law = 21-D50 ✓ WORKS).
3. og info.c authority for the offsets on 26.5: inpcb rows INHERITED
   from the 23.x branch — icmp6filt stays **0x148**, chksum 0x150,
   list_next 0x20, socket 0x40; socket.usecount = **0x23c** (the iOS-26
   branch). OUR A14_23F77 table matches (0x23c ✓) — the offsets are NOT
   the ret-5 cause.
4. So the ret-5 lives in the SCAN anchors on darwin-25: either the
   corrupted-filter layout shifted (an added/moved field between
   icmp6filt and hops — the xnu-12377 source IS on disk:
   ios-xnu-hunt/xnu-src/xnu-12377 — struct-walk gives icmp6filt ≈
   0x13c by MY hand sizes = imprecise, ±0xc off the device law) or the
   executable_name member's position moved, or the mapped window
   (IOSurface OOB map on 26.5) changed.

NEXT: the failing log = the 12's cs2_krw_log.txt — the pull HUNG
(device off USB). Replug the 12, pull, and match the loop lines against
the four law candidates above (marker law / exec-name law / window
law / offsets — offsets already cleared).


## The hunt-12's cs2 verbatim run (23F77, 2026-11-01 00:38) — FULLY DECODED, ret=5 explained

This run answers the ret=5 differential. The failure is NOT the ret-5's
"pe" fallback: everything upstream of it = one named law.

Rows:
- The spray + gencnt law FINE on 26.5: gencnt[0..2] = 0x8/0xa/0xc
  (small sequential) ✓; budget 0x5800 ✓; pcb id range 0x8..0xb006 ✓.
  -> the PIDFILEPORTSOCKETINFO blob+0x110 gencnt law = train-stable.
- **THE OOB WINDOW: `oob try0: w=4096 errno=60 (win-cap=0)` ×many,
  `oob_read kr=0x5` ×6, scan exhausted "oob_read kr-fails=65528"** —
  the fileport-backed vnode window = ZERO contiguous capacity on 26.5.
- The fallback kernel_base walk = exhausted after 0x4001 pages (the
  early-kread probe = nothing readable — expected with no window).
- `cs2_pe failed: (os/kern) failure (5)` = the ret-5 = just the final
  echo of the empty window.

LAW (the whole differential in one line): **the lab's own hop-1 law —
"cluster_*_contig EINVAL since 26.1" — IS the cs2-on-23F77 failure**: the
contiguous fileport window died on 26.x-era trains, the pcb scan reads
an empty window, and every stage after (scan / corrupt / kernel_base
walk / pe) cascades from it. The 21-D50 (17.3) still has the contig
window = the whole engine works there. NOT a new bug, NOT wrong offsets,
NOT wrong gencnt — the contig hop = the single point.

The fix paths (per the skill's existing plan):
- the Rocket (Relaxin) class: the SPTM-era PTE alias window in MIT code
  = the replacement window; on 27.x ports the Rocket plan says 15 gfx
  keys + 10 symbols from a fresh import; on 23F77 the same class =
  the PTE-alias window decode.
- OR a non-contig OOB window law (the fileport read page-walk =
  decode whether adjacency without contiguity is obtainable).
- The mini-first proof rule = SATISFIED for this class (21-D50 = the
  whole engine verbatim-working = the proof the algorithm is sound).


## The 17's cs2 run + watchdog (2026-10-31/11-01) — the law now 3-device-pinned

- The 17 (iPhone18,2 / 24A435 / T8150) cs2 verbatim = the IDENTICAL failure
  mode as the hunt-12's: `oob try0: w=4096 errno=60 (win-cap=0)`,
  `oob_read kr=0x5`, mappings 0x8000000 all scanned, log ends mid-run.
  gencnts = 0x1ba2cac.. (large sequential — the gencnt law train-stable
  there too). So the contig-window death = 12/23F77 + 17/24A435 both;
  the 21-D50 mini = the ONLY train where the window is alive.
- **The watchdog = the APP-side watchdog, not a kernel event**: the app's
  main thread blocked inside the cs2 C loop = the 0x8badf00d-class abort;
  no kernel receipt (no bug_type-110/110-class panic) from it. The cs2
  body blocking the main thread = a probe-harness law — future cs2 runs
  should run the C body on a WORKER thread (or the tap = the watchdog
  kill mid-hammer every time).
- T7 (krw7 phys-map, all passes) honest reading:
  - MapMemory sweeps on IOGPU/IOSurfaceRoot/AppleCLCD2 + DART/AVE/AES:
    maps_ok=0 everywhere (2c1/2c2) = NO MMIO window via those UCs.
  - The ONLY window T7 landed = STEP 4's **PurpleGfxMem + IOSurface
    CacheMode 0x100** (base+size rows every boot) — the
    uncached-MMIO-mapping trick (Trigon logic) = the same WINDOW class
    as the physmap STORE lane (CVE-2026-43724: physmap(PPN<<14)+acc,
    NO acc clamp on 23F77 — the lab's own live-23F77 STORE family,
    parked as "not app-reachable" since note 230).
  - The tie-in that matters: T7's CacheMode lane and the 43724 physmap
    lane = the SAME uncached-mapped-window class. If the 43724 lane
    proves app-reachable on 23F77 (or the T7 window trick reaches the
    physmap band), THAT = the first-jailbreak window answer the user
    is pointing at honestly (write into the window = kernel memory of
    the physmap band; 43722's LOAD = the kread mirror).
  - The tethered CFW (11 Pro Max boot-permissive, TFP-unrestricted) =
    the platform to validate the physmap-window MECHANICS once.
- So the T7 direction = honest and live: the physmap-window lane = the
  answer-holder candidate; next decode = the 23F77 physmap
  slide_page/physmap-band twin of the 27.x b3e7440 translator + the
  43724 STORE's user-reachable caller hunt (the parked P054/P046-class
  oracle).


## THE FULL HUNT (2026-11-01, capstone installed — 23F77 offline disasm live)

### A. The 43722/43724 walker = ONE fn, ops 1..5
0x9f1f204 (pacibsp): op-dispatch w9 {1..5}:
- **op-5 = the STORE path (43724's mirror)**: `and x,#0x3ffffffff` frame
  bits + `add x20, x10, x9` = base+PA = the physmap-band PTE write,
  NO clamp; the `tbnz #0x3f`-class bit tests; the csel-branch bfi rows = the
  flag/acc paths; `and x8,x22,#0x3ff8` = the 0x3ff8-mask class = the same
  law the lab pinned in the intel table.
- **op-2 = the u16-array LOAD (43722's mirror)**: the ldrh-uxtw#1 rows +
  the route-in6-shaped unions = the *(u16*)(info+i*2+info[2]) class.
- **caller census = ONE direct bl in the whole 38MB __TEXT_EXEC**:
  `0x9f208cc` = the 16KB-strided VM/page loop (the pager-side caller;
  16KB = A14 page stride ✓). ZERO data-pointer refs (no fixups to it).
  => the walker = pager-internal; the user-reachable-caller question =
  one level up (find the pager loop's OWN callers next decode).

### B. Stockholm (the user's gold hunch) — the ENT-Void path + the SPMI door
- **`nfc.disableentitlements` (PEBL, read in UCD::start 0x8ef1b30)**:
  set => the UC registers **IOUserClientEntitlements = 0** =
  the kext's OWN gate-void path (the workaround-entitlements answer).
  Class = boot-arg/kernel-config — settable root-only via NVRAM = the
  CFW/tethered stage (the usbliter8 boot-arg patch step).
- The kext = the **NFC<->SE channel over SPMI** (`_txSPMIData/_rxSPMIData`,
  gates com.apple.spmi.nfc[.hammerfest]) = a REAL hardware-bus I/O lane.
  With the flag voiding the ents, the SPMI UC = the ungated bus door
  (a T7-adjacent MMIO/hardware path — decode its uc methods per train).
- The Stockholm gate row = ABSENT on 21-D50 (the 17.3 train either lacks
  the kext or the gate) = the mini-first oracle = the P141 tap runs BOTH
  lanes per device; the 12/17's rows = the fleet comparison.
- The UCD method census for Stockholm = the next static decode (the
  default-locking mode carries the assertless methods; the fuzz surface =
  once an open lands in-app, the 16-sel sweep names the talking sel).


### The AudioDMAController hunt (17-only kexts, decoded)
- AudioDMAController-T8150.macho (0x8410) = the DMA-engine driver
  (ADMAChannel/StateMachine/TransferDescriptorBuilder/AXI-burst) — **NO
  UserClient strings at all**.
- AudioDMAFamily.macho = the M2M/ISOC/BULK stream family: aperture
  VA/PA/length asserts, transfer-size gates, `setExclaveProxyServiceName`
  = the EXCLAVE-proxy path (AppleEXC services), not a direct app UC.
- Verdict: not a first-class app lane on the 17 either; the x2-speed
  symptom = A/V timebase skew class (symptom note, not a lane).
- The 23F77 (12) cache: NO AudioDMAController at all (13,2 uses
  AppleEmbeddedAudio) — the 17-only family parked unless the exclave
  proxy path gets a lane later.


### p142 rows (26.5/24A435/21-D50) + the CLAMP law + the stage9 law
- 23F77 v2-faithful: set st=0, **readback = 1** = the count was silently
  CLAMPED to 1 (the knob never reached AVE2); battery survived clean.
- 24A435 (the 17, v2-faithful): the SAME row — set=0, readback=1, clean.
  21-D50: -12900 (the property absent at 17.3).
- **The clamp = the layer-FEATURE pipeline's** (v2 set
  AllowTemporalCompression + BaseLayerFrameRate = the layering path =
  the count clamped to 1). **The PoC's stage9 = the RAW path**:
  EncoderUsage=1 + RCMode=20 + **RealTime=FALSE** + the bare count =
  no feature flags = the count goes to the kext UNPROCESSED.
- p142 v4 = the stage9 mode verbatim (193431b). The 17's 24A435 = the
  row that decides: readback=16463 = the raw law landed → the encode =
  the panic point (the PoC's window-class device).
- Train law so far: 17.3 absent / 26.5+27.0-clamp-in-the-feature-path /
  the 27.0-raw path = the PoC's / 27.2 = -12900 reject.


### ATTRIBUTION correction (user's note, 2026-11-01)
The mini's hasKread/hasKwrite receipt (kslide 0x22a2c000, kbase
0xfffffff029a30000) came from the **cs2 verbatim** run (the Dopamine
ClearSword core, the contig-window train), NOT from the gate/lane
machinery or the lab's own lanes. The p142-v3 board-first gate change =
still the right fix (its gate now prints PASS via the board's committed
slide = cs2's landed state = the honest attribution); the lab's own
lane work tonight = the walls, the decode grid, and the tap rows —
NOT a KRW delivery on any device.


### p142 v4 on the 17 (24A435) — INSTANT PANIC, the honest read
Preface (user): p100 + p090 + p018 ran FIRST this boot (dirty-state
candidate). The log: EncoderUsage=1 st=0; **RCMode(-12900) = the string
key refused on 24A435**; RealTime=FALSE; count set=0; **readback = 1**
(the count CLAMPED on the raw path too — the 112705 count vector NOT
reached by our session shape); Prepare=0; ENCODE[0] st=0 clean → panic.

- NOT the 112705 count law as armed: count=1 (clamped), and the earlier
  v2 run on the SAME device SURVIVED the same count. The differences vs
  the survivor = (a) the stage9 property pack (EncoderUsage=1 +
  RealTime=false = the raw/offline path; RCMode refused), (b) the DIRTY
  BOOT (p100/p090/p018 first this boot).
- The isolation = reboot clean → p142 v4 ALONE: panic => the stage9
  shape's ingredient (the usage/offline path — a NEW lead class);
  survive => the dirty-boot law (the lab's own cumulative-state class,
  matching the one-tap-per-force-quit law's premise).
- The .ips = the Settings > Analytics pull (panic-decode law: kslide =
  KernelCache-slide + 0x8000; the videocodecd task's writer-PC = the
  AVE2 band check).


### p142 v4 on the 17 = INSTANT PANIC AGAIN (clean boot, first-tap, repeatable)
Clean isolation run: SAME panic after a clean boot, p142 v4 alone =
**REPRODUCIBLE kernel panic on the 17 (24A435)** — the lab's first
repeatable panic on that device. Same logs: readback=1 (the count still
clamped!), the 12 (23F77) does NOT panic with the identical code.

Laws this pins:
- The trigger = the stage9 shape on T8150/24A435: the EncoderUsage=1 +
  RealTime=FALSE offline path (the RCMode row = refused = an off-shape
  config) — reproducible, first-tap, clean-boot = a REAL bug lead
  (the 112705 writer site OR a sibling offline-path bug).
- Train divergence: 24A435 (T8150) PANICS, 23F77 (T8101) survives the
  exact same session shape and count (both readback=1) = chip-or-train
  differential — decode the .ips writer-PC to name which.
- Next: the .ips via Settings>Analytics = panic_decode.py (the slide
  0x8000 law) → the writer-PC's segment + the site's disasm via
  capstone (the 24A435 kexts on disk incl. AppleAVE2/AVEVTSmoke class
  = the local decode ready).


## SPTM-t8150 opened (the user's loaded blob = sptm.t8150.release.bin's own Mach-O)
The pins re-verified LIVE in the loaded session: remove_ctx_id 0x270b7ab0
decompiles with the ttbat-lock GLOBAL +0x60/0x78/0x138 + the s3_6_c15_c11_1
per-cpu + the flag-byte +0x1628 = the 820-era pins byte-true.
Decoded body: ctxid u16 @+0x18, cap 0x3f (panic 0x4000019); the ctx-array
in-use slot [+0x20 + ctx*0x18] must be ZERO else panic 0x4000016; the
TTBAT entries (GLOBAL+0x78 + ctx*0x10) must BOTH be bit0-valid else panic
"Valid context ID but the TTBAT already contains invalid entries"; the
LOCK byte [+0x60] = panic 0x400001a if already set (the mutex shape!);
then BOTH TTBAT validity bits get cleared, then [+0x80 bit0] branch.
HONEST VERDICT: the SPTM = NOT the easier target. The fn's state machine =
bounds+locks+in-use checks (the "ungated" part = only the missing DEKKER
pair — a RACE shape, but it must be entered from kernel code holding the
TTBAT context = the app never reaches it). The SPTM's callers = the
SPTM-call interface (EL2, SMC-class) = app-unreachable.
The KRW-on-17's honest lane stays the ROCKET door (the state-band fields =
the capstone session = next) + the AVE2-class conversion geometry.

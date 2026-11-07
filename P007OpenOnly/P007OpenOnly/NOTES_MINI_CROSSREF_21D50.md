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


## THE ROCKET STATE-BAND DERIVATION (24A435 disk cache, capstone) — the pin batch for the FIRST LUM1NA JAILBREAK ON THE 17

The consumer trio + the filler decoded at 0xa03d88c..0xa03da58:

- **the record array**: base = PP+0x48 ([x20+0x48]), count = PP+0x50
  (u32), stride **0x18**; record row = {+0: tagged ptr (the 0xc8a2
  tag-check law, eor/prefiltered), +8: u32 value (STR w19), +0x10: u8
  valid (STRB #1)}.
- **the filler loop** (0xa03d92c): for i in 0..count: PAC-tag check on
  the entry ptr; store w19 at [+8]; store 1 at [+0x10]. w19 = the
  caller's value (the submit's per-entry datum).
- **the dispatch wrapper above it** (0xa03d8b0): [uc+0x160] lock take
  (0xa05ebb0/0xa05ebf0 pair), the walker over [uc+0x168] list: PAC
  autda #0xcda1 + blraa via [vt+0x90]! — **the SAME PAC-dispatch LAW
  as the IOSurface vt48_setter and the fence chain (the 0xcda1
  modifier is FLEET-CLASS, on every kext's vt-dispatch)**; per-node
  call + [node+0x30] next; then the fill loop.
- **the readback trio**: idx = [entry+0x424] (sxtw); base = PP+0x48;
  off = idx*0x18 + {8, 0xC}; PAC-safe csel (the 0x2bad modifier on
  the OOB-catch); fn A returns [+8], fn B returns [+0xC].
- DERIVATION VERDICT: the state-band's own field set = the record
  {ptr, value, valid} trio at 0x18 stride; the 17.x/26.x stateControl/
  stateLength/stateSubmitObject/stateAddressBias names map onto it
  CLASS-WISE (per the FIELD# law: match by class + stride + slot
  index, never by KVA). The submit chain (sel 0x24 → owner → 0x88 →
  res → state 0x530 → PP 0x158 → PP+0x48 array) = CLOSED statically.
- NEXT: the device row (the Rocket submit sel-0x24 on the 17 via the
  P045/P065-class UC call with a REAL owner = the tap to build: the
  sel24 call + the state/readback census = the door's device proof).

## p143's device row (17/24A435) — the door's census landed
- [1] IOGPU open t1 = kr=0 (conn=0x6f13): t0 = 2c7, t1 = OURS (the live
  IOGPU connect on 27.0 = the p115 real-queue class).
- [3] the census: sel 0x24 + 0x20..0x29 = all 0xe00002c2 with the
  zeros-in call = the OWNER-GATE reply class (the fn reads [uc+0x120]
  first; NULL owner = bail = the designed reply row).
- NEXT HOP = the owner-carrying call: populate [uc+0x120] via a REAL
  resource/owner attach to this connect (the ioGpuUserClientTypeStatic
  row = 0x7f20260 via the gtype-slot fn), then sel 0x24 with the REAL
  pair. Door talk = the submit; door silence = the 2c2 wall named.

## THE 17-KRW PIN BATCH (2026-11-01, the first-jailbreak program)
- p143's device row: IOGPU t1 connect = LIVE (0x6f13); the sel census (zeros) = the owner-gate 2c2 reply class; next hop = the real-owner call.
- The gtype-slot fn (0x84f2124) byte-decoded: the class ctor = the metaclass 0x7f30218 + classSize 0x138 + the singleton store 0xb8a6440 (the ioGpuUserClientTypeStatic law's fn shape); the pacda-cda1 store row = the fleet PAC law again.
- The AVE2 panic = 5+ reproducibles, SAME pc every time (user-confirmed) = the single-site law = the 112705 writer cluster's twin live on 24A435.
- The KRW self-test = universal already (the board-gate code runs on every device): what the 17 needs = a REAL primitive behind its own lane; the Rocket owner-hop = the door's remaining decode.

## p069 ON THE 17 = THE MAP LANDED (2026-11-01 batch)
p069 (24A435): memory entry kr=0x0 size=0x4000 port=0x13d493 →
**mach_vm_map kr=0x0 addr=0x1126ac000 (the makeMapping consumer)** —
the 43684 map path LANDED on the 17 (the route-D md-port class on the
= = = = = = exercised once, verdict line: "mapping path exercised once.
Increment is IOMD+0x68 (not +0x34)").
The honest KRW read: the map = OUR OWN surface's memory-entry = a
kernel-mapped OUR page = not a kernel-read. The law stands (43748-class
read needs the copyout of kernel bytes we did not write).

## The AVE2 panic-site decode (24A435, capstone) — the honest row
The panic pc (0x8723188, AVE2 __TEXT_EXEC +0x5A78) = inside the
FAIL/LOG path: the pc row = the alloc/oslog cluster entry (`mov w0,#0xc4;
bl 0x88485dc` = the size-class alloc; `bl 0x88be9ac` = the consumer; the
0x7331xxx/0x72ea xxx fmt-strings = the oslog rows; the -0x3eb = the
0xfffffc15-class return = the alloc-fail law's row). The WRITE that faulted
(far=0x59+(N-163)<<32) = the ALLOC's own zeroing/fill into a buffer whose
SIZE scaled with the (unclamped-internal) count — the far's high word = the
count's remnant ✓ (the PoC formula law). The alloc = 0xc4-class (196 = the
the = = = = = = = = = = = = = = the = = = = the (the = = = = = = = = = =

## THE 17 NIGHT BATCH (2026-11-01, the full tap list) — the honest board
STRONGEST NEW RECEIPT = **p116: the deterministic SANDBOX-ESCAPE class
(6/7 out-of-container reads through an in-container extension)** —
/etc/passwd + services + the GlobalPreferences + networkd reads = the
NOFOLLOW gap's receipts on the 17; deterministic (zero race); the
policy-unpatched law (upstream says live through 27.2). This = a REAL
privilege-boundary chain ROW (not kernel; the honest class).
The night's misses (all honest, all now measured on the 17):
- p133: p010 = all-2c2 on the 17 (the 23F77's law-row differs);
  p114 sel-8 = the 2bf+64KB class but ALL-ZERO payloads = the 17's
  serializer = empty this boot (the "payload deeper" law falsified
  on the 17 = honest).
- p134 route A = no arm (the engine did not arm OUR conn class).
- p122 (17!): freer + detach + replace = kr=0 both; 2000 raced reads =
  ZERO kernel-shaped occupants = the zone's natural population =
  user-class (the Shape-1 ceiling measured on the 17).
- p125 Cinder27 = the faithful ring, all-notify-rejected = the class
  documented, not armed (same verdict as their own twin).
- p023/64747-VT = the create-OK-on-everything + the -10279 tiny-encode
  soft-fail = the 64747 lane stays closed from the app (both devices).
- p022GC v42 = H1 accepted-not-instantiated; H2 = the MAC-deny on any
  fd path (the 0xa5d79d8 class) = the 536 lane's honest negative.
MIE note: the MIE camp (the tracker's frame) = the demo-class device
work; our live lanes tonight = kernel-object/VT/IOKit class = not
MIE-dependent; the chain composition note stays in the ledger.

## THE ROCKET DECODE REPORT (agent #1, 24A435 cache) — the corrections + the gap rows
- **NO selector writes [uc+0x120]**: the owner = minted at OPEN time by
  `deviceUserClientStart` (0xa024970): the value = the [uc+0xf8]-object's
  vt+0x588 blraa return, args = the client task/token [uc+0xd8] +
  [uc+0x128]; then 0xa05ed00 → [uc+0xe8]; then 0xa0403b8(owner) checks
  "com.apple.private.gpu-restricted" / "developer.gpu-restricted" →
  sets [uc+0x103] bit = the TABLE-CHOICE boolean (open-time, not a
  per-submit gate).
- **THE ROW-NUMBER CORRECTION (off-by-11)**: the submit fn 0xa02299c =
  **sMethods row 0x19** (both tables; the pinned "sel 0x24" = the
  index wrong, fn VA right). Row law: {fn (0x8030-AUTH-fixup), kind@+8,
  checkIn@+0xc (0xffffffff = variable), out@+0x10, aux@+0x14}.
  A[0x19]: kind=4, variable struct-in, out=1; the asserts name the
  input laws ("cmdBufArgSize does not match config" / "total size
  overflow (%llu * %llu)") — **the SAME assert-string set as the
  23F77 sel-25 chain's = the 27.0's row-0x19 = the sel-25 machine's
  TWIN (cross-train law)**.
- **NO ENTITLEMENT CHECK in the submit row's first 0x150 bytes** — the
  door's real gate = the INPUT SHAPE only. The owner-getter row 0x37
  (0xa0240cc, cin=0/out=scalar, reads [owner+0xfc] bit0) = the closest
  userland-visible owner row.
- **THE VALIDATION GAPS (the new lead class on the SAME UC)**: (i)
  0xa021afc = release-then-clear: the owner object RELEASED before
  [uc+0x120] zeroed (+0x110/+0x108 same) and the release path's
  locking vs the readers' device lock (the 0xa040878/0xa01fbf8 pair)
  = not evidenced in-band = **the 64788 stalepage/wrapper-lifetime
  family's shape on the SAME owner field**; (ii) deviceUserClientStart
  writes the owner with no previous-value check (idempotence unverified);
  (iii) [uc+0x128] consumed into the minting call, teardown zeroed
  only — bound unestablished.
- B0nus: the kext's assert strings name every s_ handler (s_new_resource
  0x79944a6, s_submit_command_buffers 0x799461d, ...) — the row-by-row
  sel naming = derivable (the fnnames script pattern, /tmp/gpu120/).

## THE AVE2 DECODE REPORT (agent #2, 24A435 cache) — THE MECHANISM DECODED
Corrections (honest):
- Our pinned (pc,lr) pair = FAKE-NEIGHBOR class (the slide-pair law!): the
  pc row = `mov w0,#0xc4` (non-faulting); the panic fn = 0x8722d30 (the
  slice-header syntax-writer wrapper; its `str w8,[x22]` at +0x597c = the
  far==param_6 row); the 0x88485dc = a LOG-CATEGORY gate (0xc4 = category
  byte, not a size!). The far-law `0x59+(N-163)<<32` = a PROJECTION
  (0x404F appears nowhere in the kext) — the RAW truth = far=0x59, x19=1
  at N=16463.
**The COUNT-SCALED FILL = the DPB cluster — fully decoded:**
- ManageDPBBuffer 0x8738514: pool base = ctx+0x2e0, stride 0x80 (LSL#7),
  index = the RAW count field [ctx+0xb64], **NO capacity check**; the
  0x2bad/0xc8a2 csel pairs = pointer-tag idioms, NOT bounds checks.
- The DPB-pool INIT: `ldr w8,[ctx,#0xb60]` (count N from [cfg+0x55c]);
  loop i=0..N: entry = pool + i*0x80, ~16 stores/entry + the double
  linking. Bound = the raw config count ONLY.
- **THE OOB CLASS = THE SIZE/FILL MISMATCH**: if the pool was SIZED from
  the clamped count (our readback=1 row!) but FILLED by the raw N =>
  the destination is unbounded relative to the allocation = the OOB
  write class — THE MECHANISM OF OUR REPRO, decoded at instruction level.
- far=0x59 read: the DPB entry store `*(u8*)(entry+0x5a) = *(frameSettings
  +0x7572)` gives far = entry+0x5a = 0x59 when entry = the -1-sentinel
  slot ✓ (the fn's own -1 law: IndexLongTermReferenceFrameToBeReplaced).
- The property: sSessionCfg.sEnc.sAlgCfg.sGOP.iNumOfTemporalLayer; the
  ONLY existing check ("0<=&&N-1<=7", assert 0x72ffd47) lives in the
  DecideNumOfTemporalLayer path — THE FILL PATH HAS NO SUCH CHECK.
**The second cluster = the WRITE-THROUGH-POINTER (the aimable candidate):**
- The unvalidated intake: [ctx+0x110] = a raw u64 arg (no range/mask).
- The mapper 0x87a4b4c: iterates ALL 64 mask bits; slot = raw
  array[bit]; addresses ctx+0x20+slot*8 / syndrome+slot*8 (id*8, no
  size check); FINALLY the write: `*(u64*)(*(u64*)(syndrome+slot*8)
  +0x20) |= bit` — an indirect write through an OOB-loadable pointer,
  no bound beyond the ctx+0x110 AND anywhere. ESR/far fits.
**AIMABILITY = YES on both knobs**: (primary) the count = our repro
path; (secondary) the raw u64 mask → the mapper's indirect write —
which VT property feeds it = the next selector-arg naming hop.

## THE TRIPLE-CONFIRMED PANIC LAW (2 new .ips, 2026-11-01)
- panic 121707: pc 0xfffffe0050bab188, Kernel slide 0x48488000 →
  unslid = 0x8723188 ✓
- panic 122649: pc 0xfffffe003fa13188, Kernel slide 0x372f0000 →
  unslid = 0x8723188 ✓
- + the first pair's = THE SAME UNSLID PC **0x8723188** in AppleAVE2
  __TEXT_EXEC (the panic fn 0x8722d30-class), far/x0 = 0x59, x19 = 1,
  esr 0x96000046 (write) — **the register fingerprint IDENTICAL on
  every repro across boots with DIFFERENT slides** = the single-site
  law is now boot-independent (the KASLR-invariance of the bug's own
  path = the reproducibility receipt class).
- The slide law REFINED (the agent's corrections + these rows): for a
  kext-band/unslid decode = use the panic's OWN "Kernel slide" row
  (0x48488000/0x372f0000-class), NOT the text-exec slide.

## p143 v2's 17 row (12:42:45) + the rest of the tap ladder — the honest end-of-night board
- p143 v2 on the LIVE t1 open: rows 0x17..0x1B = 2c2; **the owner-getter
  row 0x37 = ALSO 2c2 (cin=0!)** = the connect-class wall (not a
  per-sel shape law): the type-1 connect on 27.0 either lacks the
  sMethods rows entirely (a different UC class than the type-0's) or
- p136 v3 on the 17: the b1b2 engine = the SAME laws as the 12's (the
  phase1 GVA bind ✓ / phase2 stale ✓ / phase3 the p027 2c2 = the
  SAME qid/stride law (qRef+0x538 not heap on the 17 = the 23F77's
  law-row DIFFERS) / phase4 = no land without the latched kick) = the
- p126 decmpfs = 0 hits (their own twin = the same zero = the class's
  honest miss/engage-dependence = documented).
- p140 on the 17 = the type-0x1b/kaddr-hidden law = 26.5+27.0-class
  IDENTICAL ✓ (the locator law's cross-train triple).
- p131 v2 = the QL control + the trigger = both PARSED CLEAN (the
  magnification-heavy config = the known-clean config class) = the
  QL detour = the honest no-receipt shape on this config.
**END-OF-NIGHT HONEST BOARD on the 17**: the static work = complete for
this session's scope (the DPB mechanism + the Rocket rows + the tools +
the corrections). The remaining = TWO naming decodes (the mask-intake

## AGENT-#3's REPORT — the night's decisive corrections (24A435)
1. **THE SLIDE LAW WAS MINE-ERROR**: the correct unslid = value − the
   **KernelCache slide** row (the "Kernel slide" row's VALUE = KCS+0x8000
   — the memory's law describes the row value, not the constant!). All
   prior cluster VAs = +0x8000-shifted (real fns, mislabeled frames).
   For bug_type-210: use KCS + the discriminator "unslid pc must MATCH
   far/esr-Set" (the cheap check).
2. **The TRUE (pc, lr) = 0x872B188 / 0x88410C4** (bit-identical across
   boots; 17 backtrace frames unslide identically under KCS). The pc
   row = `stp x0,x0,[x0]` — an intrusive-LIST-INIT write with x0 = 0x59
   = 1+0x58 ✓✓ (x19=1 = the GARBAGE object; far = x19+0x58 ✓).
3. **THE TRUE CHAIN (innermost→out, ALL AVE2)**: leaf list-init 0x872b180
   ← session-object reset 0x8840fec (re-inits lists at obj+0x58/+0x78;
   obj = x19 = 1 = GARBAGE!) ← wrapper 0x88411ec ← codec-instance
   teardown 0x87913b4 (3 slots at ctx+0x147b0; slot0 HELD 1) ← codec
   stop/close 0x8794328 ← release 0x8795390 ← fn 0x88da9a8 (row16)
   ← ... ← kernel. **The class = the codec-instance array's STALE slot
   (a failed-instance sentinel/UAF shape) surviving into teardown = a
   real dangling-pointer UAF on the same kext** — the slots created in
   0x8790cec (3 sites), config feeds the SETUP only; the slot VALUE =
   never a config field = the 1 = a stale/bogus pointer.
4. **The DPB pool = an INLINE ctx array** (base ctx+0x2e0, stride 0x80,
   legit capacity ~17 entries before the bookkeeping at ctx+0xb60); the
   fill = UNBOUNDED (no clamp; only the lower/sign guards) = over-capacity
   fills MARCH INTO the ctx's own fields (first the bookkeeping, then —
   larger — the ctx's pointer-bearing fields: ctx+0x2d0 sub-object, the
   ctx+0x147b0 slots, ctx+0x1f60 flags, ctx+0x2270...). = a linear,
   kernel-pointer-shaped clobber = a REAL corruption primitive.
5. **The DPB entry's +0x58 = a CONFIG-SUPPLIED u64 (userland knob)**
   (the +0x68/+0x70/+0x78 = in-kext object-tagged copies; the fill's
   link fields = sibling pointers).
6. **physRW conversion = NO** (honest): no path to physmap/kpages.
7. The panic-caller kernel frame = 0xB4351F8-class ("panic caller" row).

## AGENT-#1's REPORT — THE MASK-INTAKE KNOB NAMED (24A435)
**The userland knob for [ctx+0x110] = AppleAVE2UserClient SELECTOR 2
("IO_Config")**: structIn = EXACTLY 0x38 bytes, scalarIn/Out = 0,
structOut = 0x20; the mask = the RAW u64 at structIn+0x30; Config
(0x88d3b90) stores it UNVALIDATED into [session+0x110]
(stp/str @0x88d4008-10; only size checks; [0x118..0x140] zeroed).
NO VT property reaches this intake (the property-parse hypothesis
REFUTED — the temporal strings belong to the GOP parse only); NO
entitlement/policy strings anywhere in the row-fn region.
- **The TRUE sMethods (the 16-row pin's SHAPE corrected)**: 16 rows
  stride 0x28 at __DATA_CONST 0x7f902d0 = {method, scalarIn@+8,
  structIn@+0xc, structOut@+0x14}: row0 IO_Open(0x88d24e4, in 0x768/out
  0x38), row1 IO_Close, **row2 IO_Config(0x88d3804, 0x38/0x20)**, row3
  IO_Prepare(0x88d40c4, 0x12c08/0x20!), row4 IO_Start(0x12c18/0x150),
  row5 IO_Stop, row6 IO_Process, row7 IO_Complete, row8 IO_Flush,
  row9 IO_Reset, row10 IO_Print, row11 IO_PowerOn, row12 IO_PowerOff,
  row13 IO_StartUp, row14 IO_ShutDown (names from the "%s::%s" xrefs;
  the t8150.ave2.uc_methods pin = a bridge-only spelling).
- **The consumer = the ENCODE LOOP's map step**: per-surface mapper
  0x87734f0 calls chk 0x8879dc8 with mask = **0xffffffffffffffff** and
  [session+0x110] AND-masked in → the object-list walker 0x8777d2c from
  the 8-site encode-map family (0x880b6ec..0x880c278) = the mask =
  consumed whenever the session maps surfaces (IO_Prepare/Start/Process
  rows → CreateSurface CRSR1/CRSR2 → the configure chain's rows).
- chk's gates: selIdx<=3, "surface is not created", [ctx+0x119] bit2,
  the 2-bit-per-index rights read at ctx+0x120; the mapper intake
  itself = ungated (the write-through: *(u64*)(*(u64*)(syndrome+
  slot*8)+0x20) |= bit).
- Also: the state machine's gates on IO_Config = "IO_Open first"
  (m_pcIODrv != null && the notification port == 0).
- AVE2 fileset: LC_FILESET_ENTRY idx 35; the fixup law re-proved.

## AGENT-#2's REPORT — the 2c2 mystery SOLVED + the door's full userland law
1. **The all-2c2 = the PROBE's shape flaw**: every row validates its OWN
   input counts in-band (s_submit: scalarInputCount != 4 → 2c2 directly;
   the cin=0 rows reject a 4-scalar call!) — the uniform probe could
   never satisfy two shapes. The asyncReference gate = also real.
2. **THE GATE POLARITY = REVERSED**: gate fn 0xa024d94 (the vtable row
   0x82f6378): [uc+0x103] bit0 SET → table B (the 0x82f69f0 stub-table:
   rows 15-0x36 = the 2e2-stub fn 0xa0240d8!); bit0 CLEAR → table A
   (0x82f64b0 = FULL). [uc+0x103] = set by deviceUserClientStart via
   0xa0403b8 = the gpu-restricted PAIR of strings = "client IS
   restricted" → the RESTRICTED app gets the stub! OUR UNRESTRICTED
   app = bit0 clear = TABLE A FULL. [uc+0x100] bit0 = the
   dispatch-armed law (0 = 0x2d8 NotReady — NOT 2c2).
3. **THE TYPE LAW**: newUserClient 0xa04e5b0: ONLY type 1 = the
   IOGPUDeviceUserClient (type 0 = 2c2-refused outright; type 0x21 =
   the MemoryInfo UC). Our p143's type-1 connect = the right class.
4. **THE SUBMIT'S USERLAND SHAPE (complete)**:
   - scalars {s0 qid 1-based (0→lookup fail), s1 count, s2 stride,
     s3 unused}; structIn = count×stride; **SIZE LAW: structureInputSize
     == count*stride exactly** (else "bad structureInputSize").
   - stride MUST == *(u32*)([queue+0x530]+0x260) ("cmdBufArgSize does
     not match config") — THE 27.0 stride-law source pinned!
   - entries: +0x10 u64, +0x18 u64 (both to the per-element submit;
     +0x10 nonzero = the SECOND wait/copy via [q+0x430]), +0x20 u32
     gate (nonzero = the refresh path via [q+0x488] then vtbl+0x80).
   - lookup: owner [uc+0x120] → +0x88 registry → mutex @+0x20 → table
     @+0x10, count @+0x28 (8-byte ptr array, 1-BASED).
   - pre-checks: FUN_0xa050604([q+0x530],q) nonzero else 0x2d7 Offline;
     q+0x428/q+0x488 non-null else 0x2bc.
   - **OUTPUT: scalarOut[0] = (u32)*(q+0x520) — 8 = submit-creation
     FAILED, 0 = CLEAN** (also stored into [cfg+0x2e0] after the loop).
   - the 23F77's sel-25 4-scalar shape = the SAME machine (the cross-
     train twin CONFIRMED; the stride-law's source = now pinned).
5. Honest unknowns: rows 1-24's per-row names (heuristics only); the
   AGXDeviceUserClient table (ctor 0x84f21b4/gMeta 0x7f356e8 named,
   not decoded); the *(0x82fea78) tail-object's identity; the
   [uc+0x100]-before-submit ordering proof; agent-1's row-list differs
   in ONE spot (row 0x19+... the = the).
   The capstone tool notes: adrp imm = SIGNED; restart-on-undecodable
   walkers required; full-fn-bound scans (the ret-stop miss law).

## THE 17-JAILBREAK PREP BOARD (2026-11-01, the "one build away" snapshot)
- The taps that exist now, all shipped: p143 v5 (the door: the qid law
  + the entry-content ladder + the reply-byte stride), p144 (the AVE2
  mask intake: IO_Config), p142 v4 (the reproducible trigger), p134/
  p135/p136 (the route map), p093 (the DB), p116 (the sandbox receipt).
- The offset table (T8150_24A435) = BOTH apps synced (the real pins).
- The static decode state: the door's userland law = complete (the
  submit shape/stride/entry/out laws); the mask intake = named; the
  panic chain = the UAF+fill composition; the slide law = KCS-fixed.
- The gate + the post-KRW pipeline = built, receipt-controlled.
- THE REMAINING (all bounded): (1) p143 v5's device row (the run) —
  the entry-content rows = the last 2c2 candidate; (2) if the submit
  still refuses: the config-echo decode (out+0x20's pair = the stride
  law's own source candidate); (3) the AGX UC table (queued); (4) the
  row-name heuristics for rows 1-24.

## THE BUILD-ORDER FOR THE COMPOSITION NIGHT (the highest-chance KRW path)
Written for the next builder (the fresh build of the night's lead, all
law-sourced; nothing here requires re-decode):

### P142-v6 "COMPOSITION" (the one new probe; the highest-chance design)
Law sources: agent-#3's DPB field map + the UAF slot array; agent-#2's
door/stride laws; the p110 claim rows.
1. **The spray stage FIRST**: IOSurface groom battery (the p027-class
   buffer battery: 4096+ alloc/attach/hold rounds, the sid band
   0x10000+) — the fill's overshoot target = the ctx's own fields + the
   zone AFTER it; the spray = the reclaim-candidate population (the
   claim window's p110 law = the pop == the victim sid's slot-reuse
   behavior = the groom's proven ingredient).
2. **The count knob ROUND**: VT HEVC session (the p142-v4 stage9 mode)
   with the count knob (Documents/p142_layers.txt); THE COMPOSITION =
   each count-value session runs INSIDE the live spray battery (a
   second thread holding 64 surfaces live) = the fill's overshoot
   lands INSIDE the contested zone (the reclaim-candidate class).
   HONESTY: the count values only in-bounds first (4/8/16 — the real
   session shapes; the 16463-class = the PANIC row = the receipt tap,
   separate, one tap per boot, never composed with the spray).
3. **The discriminator**: post-session — three honest rows:
   the spray pages' content diff (a 0xBB/0x41-class marker landed where
   a fill wrote: any non-spray-value bytes = the fill's overshoot receipt — the honest read: any
   non-spray-value bytes in a held page AFTER a count-session = the
   fill's overshoot receipt-class = the aimability row].
4. **p110's pairing**: run the claim-window round INSIDE the same boot
   (the honest shape: the p110 round + the
   fill-session = the two proven behaviors in ONE window = the
   composition's second axis.
5. **The gate**: the kread32 receipt law ALWAYS.
### Not tonight's (honest OWE list)
- The door's stride value (the = [q+0x530]+0x260 read = needs the read;
  the config-echo decode = the out+0x20 pair).
- The AGX GC table + the *(0x82fea78) tail-object identity.

## 2026-11-01 late — params-blob decode INTEGRATED + the kill-shot triage (the canon 25 cross-ref)

### The params-blob agent's report (a2185c0f; 62 tool-uses, 23F77+24A435 caches) — the DPB count's TRUE intake
- **VERBATIM: cfg+0x55c == structIn+0x55c — NO REMAP.** The pool-init's site reads the count
  DIRECTLY from the userland struct-in blob pointer (IO_Prepare, the 0x12c08 blob). The count
  = sSessionCfg.sEnc.sAlgCfg.sGOP.iNumOfTemporalLayer; +0x560 = its duplicate
  (AVE_GOP_DecideNumOfTemporalLayer 0x88ba790 str-copies +0x560 -> +0x55c; called once from
  0x889c234). The VT property path was a different, GOP-path rewrite of the same slot — the
  BLOB FIELD is the speakable one, not the property.
- **The setter chain**: cfg+0x550+0x554 pair -> ctx+0xb68; **cfg+0x55c -> ctx+0xb60 (THE
  COUNT)**; cfg+0x558 -> ctx+0xb70; index=0 (the str site @0x8735fd4-class).
- **The 3-validator envelope**: (i) the [0,8] CheckInfo assert = LOG-GATED (the weakest —
  scope disarmed = it only logs); (ii) the D5 verifier 0x873358c (num_ref_frame vs
  m_MaxDpbSizeForThisProfileAndLevel [clamp16 @0x88ba5dc]; >=17 FAIL; <2 && no-long-term FAIL
  = HARD 0xe00002bc; [ctx+0x14] bit0 = the <2-skip door candidate) = HARD; (iii) the
  count-copy itself UNBOUNDED (no capacity check — the pool's only walls = those 3 rows).
- **The fill transform**: pool entries 0x80-stride from cfg's 0x50-stride records
  (cfg+0x40 = the first record field) — mapped field-for-field.
- **Pool-init caller**: FUN_0x889f894 (per-FRAME encode path; 6-condition gate;
  ctx = frameCtx+0xcb8, pool = frameCtx+0xf98).
- **BUILDER NEXT (owes)**: a blob-first tap under the no-guessed-shape law — the sGOP
  section shaped lawfully; the REST of the 0x12c08 blob from the validator-decode notes,
  never invented. Offsets pins go into T8150_24A435_LabOffsets.h WITH the tap.

### The kill-shot triage (the user's cross-ref push, answered against the corpus 25 canon)
- "P122 kill-shot" IS in the app (both): rig row `swordforge` — "P122 SwordForge. combined
  64788 KRW test (freer-reclaim-read)" — and main "P122 SwordForge (combined 64788 KRW test)".
  Chained by design (freer P009 -> same-CPU mag reclaim -> sel36 raced read -> consumer
  pending -> gate); lawful verdict: hasKread=NO by law (glue doc: user<->user IOMD;
  install != KRW; Shape-1 measured 0).
- The pending row "combined p110-claim + p122-raced-reader on the SAME reclaimed slot
  (one tap)" = **RETIRED BY CANON**: the 25 note pins the 64788 RECLAIM zone =
  IOGeneralMemoryDescriptor 0xb0 (variant A) and states NOT variant C (IOSurface+0x30 =
  a DIFFERENT class) — the two lanes free different classes; a same-slot composition =
  a guessed shape (the no-guess law). NOT building it.
- The canon's real PATH A "unrun" kill-shot = LightSword **lsabc D** — RUN + MISSED
  2026-10-15 (FUTURE.md: spyConfirmed=1 "alias GART is not independent"; [D] vm_remap
  "not GPU-shared" = 3 independent proofs) -> LightSword PARKED on its own kill-shot miss.
  PATH A is a parked lane, not an open step.
- **THE LIVE LADDER tonight**: p147 teardown-cycle (the stale-slot UAF window), the p110
  (b)-row falsify re-tap (leakgate-on arm), and the blob+0x55c intake law above.
  NO cross-lane mashups.

## 2026-11-01 18:5x — the evening device rows decoded: p147's calibration, p148's honest hold, the %s bug, p146 v2
- **p147 v1 (24A435, 18:36:31) — the CALIBRATION row**: the FULL 24-cycle battery ran in ~1.0 s
  (~25-30 ms/cycle, all st=0 rows) with the 80-page spray LIVE; the discriminator = CLEAN
  (0 foreign bytes in 0/64 + 0/16 pages); the gate FAIL/HOLD (hasKread stays NO). The cycle
  rate = the ladder's calibration point — the knob (p147_cycles.txt) now scales the battery.
- **THE MOJIBAKE = MY BUG, not corruption**: the cycle line's last arg = an NSString printed
  with `%s` — CFString dereferences the OBJECT POINTER as a C string and prints the isa bytes
  after "ms" (the same stable garbage per line = the constant-string address). Log-only;
  NO evidence bytes affected. FIXED v1.1: %s -> %@ (clang-checked).
- **p148 v1 (18:39:12) — the REACH row, as designed**: AppleAVE2Driver open t0 = 0xe00002bd
  (not-privileged), t1/t2 = 0xe00002e2 (exclusive — the VT/hevc services hold the encoder),
  'AppleAVE2' = NO SERVICE. The honest HOLD = the direct-UC blob arm stays decoder's work;
  the blob+0x55c law's userland reach = the p142/p145/p147 property-composed lane for now.
- **p146 v2 (the line-per-knob setter)**: p146_set.txt line1 -> p142_layers.txt (18),
  line2 -> p147_cycles.txt (24), line3 -> p148_gop.txt (2) — each with the readback VERIFY;
  single-line = the legacy row; defaults on absent. (The user's catch: v1 wrote only
  p142_layers.txt.)

## 2026-11-01 18:4x — p146 v2's device row + the NO-PUSH LADDER arm (the user's catch, fixed)
- **p146 v2 (18:44:41)**: the ladder ABSENT -> defaults 18/24/2 written + all three VERIFY
  rows clean; lswkrw_arm.txt = SET (the leakgate-on class armed); the flags state printed.
- **The catch: p146's ladder needs a PUSH — and the push channel = the wedged one**
  (p146_set.txt absent on-device). The setter bypasses the pull-side wedge, not the push-side.
- **The fix = the ROW-PRESET arm (no push at all)**: dedicated rig rows call
  P147Lifecycle.setPresetCycles:(v) then tap; the preset OVERRIDES the knob file for exactly
  one tap (consume-once, cap 200, the source named in the log). Shipped rows: x60, x120,
  x200 (the cap). The afc push law stays documented as the alternative channel.
- **p147 18:45:34 = the second calibration row (identical shape)**: 24 cycles, all st=0,
  ~25-32 ms/cycle, discriminator CLEAN again (0 foreign bytes in 0/64 + 0/16; the clean
  row class twice in a row), gate FAIL/HOLD. The ladder's climbs = the x60/x120/x200 rows.

## 2026-11-01 18:47-18:53 — the 18:50 fleet batch decoded (the 17: p110's (b) AGAIN, p122's ceiling row, p147 clean x2)
- **p110 v2.5 (18:47, THE 17 — second on-device (b))**: the dial0 arm; 58/64 rounds (c)
  claim-won-candidate, 6 (a), then the ROUND-64 alias-path FAULT = outcome (b) AGAIN —
  window-WON now caught on the 17 TOO (the 12 caught its own ~18:14). The class repeats
  across SKUs/boots = the attestation reproduced. STILL NOT KRW (the note-270 law).
- **THE (c)-DETECTOR'S HONEST REFRAME (the saturation law)**: this boot's sids cycled
  {0x107,0x108,0x10b,0x10c} — pop sid == victim sid nearly every round = SID-NUMBER reuse
  (the counter's own recycle), NOT strong slot-reuse proof; the 62-63/64 (c)-rate = detector
  saturation. The marker-divergence law NEVER fired. The (c) class = proxy-class ALWAYS;
  per-round (c) rows near 100% = the detector ceiling, not 58 windows.
- **p110's own %s-on-NSString bug class**: the IN-FLIGHT/returns/pairing lines printed
  (¿KÎÏ) — the same CFString %s-object bug (the log-only class). p110 v2.6 fixed (%@),
  plus p143/p145/p147's receipt-row "byte class=%s" -> %@ (the fix matters because the
  receipt row is exactly when the garbage would print). All clang-checked.
- **p122 (18:50) — the ceiling row REAFFIRMED on the 17**: 2000/2000 raced sel36 reads
  out of the freed slot = user-class (kshape=0); the zone's natural population measured
  user-class on-device; verdict honest (hasKread=NO by law).
- **p147 18:53:57 = the third clean calibration (all st=0, ~25-32 ms/cycle)**.
- **THE BANDIT DATA: leakgate-on n=0 — NEVER SAMPLED.** The untried arms (popearly /
  leakgate-on / leakgate-off, ucb=1e9) = the next p110 re-taps' picks — leakgate-on =
  the KVA-disclosure pairing = the LIVE next device step.
- WHAT IS LEFT FOR KRW (honest): (1) p110 re-taps until the bandit samples leakgate-on
  (the sel-8 pairing = kernel-range KVAs arriving in OUR output buffer = disclosure class
  = the material, never kread); (2) the p147 x60/x120/x200 ladder; (3) the p148 fresh-boot
  re-tap (the 2e2 holder may be momentary); (4) the honesty work (the (c)-saturation law
  is now the detector's own caveat). Parked/stopped: PATH A (lsabc D ran+missed), PATH B
  (the operator's kalloc.3072 STOP), the direct-UC blob (exclusivity). hasKread stays NO
  by law tonight unless a kread32 receipt lands.

## 2026-11-01 ~19:0x — the efficiency round: the verified gates + the targeted-sampling row
- **CI VERIFIED (the GitHub public API — gh is unauthenticated here)**: the latest push
  (c115165) = ALL THREE jobs GREEN (Validation / Build IPA / **Build Lum1na-Debug IPA**)
  — and the four prior pushes (be4bb6c..4a960c1) all built. The rig IPA = real, current,
  installable. (Xcode Build = the parallel unsigned-build job = cancelled-by-design rows;
  the AGENTS gate = Lum1na Build.)
- **THE TARGETED-SAMPLING ROW (p110xleak)**: the efficiency fix for the bandit — instead of
  blind re-taps until the UCB sweep reaches leakgate-on (n=0), the explicit row calls
  P110SurfaceSwapClaim.forceLeakgateArm() then tap; the preset overrides the bandit pick
  for exactly ONE tap (consume-once; outcomes record under the preset's arm id = the shared
  ledger stays one-source; the override named honestly). Same consume-once law as the p147
  x60/x120/x200 rows.
- HONESTY NOTE: this row = the tap's ONE device step toward kernel-data-in-userland (the
  sel-8 pairing). Disclosure class; never kread; the receipt law unchanged.

## 2026-11-01 19:30 — the p101 wrap run + the leakgate-on first row decoded (the user's chaining push)
- **p101 v2 (T8150, 19:30:20) — the RETAIN-WRAP PROVEN on-device**: 65,537 retains, kr=0x0
  every round, no ceiling (the B6-class law live on 24A435); the u16 dmaref wrap theory
  measured. The chain honestly STOPPED at the release route: the gate oracle did NOT
  corroborate (sel-census out+0xc = 0x01010101 CONSTANT through map/unmap/remap — the
  [md+0x98] field never moved under the driven ops = wrong observed MD or the 23F77
  sel law drifts on 24A435), and the twin PANICS on underflow -> honest SKIP (the route
  guard held). Chain state: wrap=X -> release-route=UNPROVEN -> NO UAF. Also a WRITE-lane
  design at the end (page-list confusion -> P102), not a kread lane.
- **p110 v2.6 (19:29:54) — the leakgate-on first device row (T8150) BEFORE its (b) death**:
  the ROW PRESET fired (leakgate-on forced, consume-once verified in the log); the
  23F77 v5 sel-6 contract = 2c2 REFUSED on T8150 (outLen 4008) and sel-8 = 0xe00002bf +
  64KB all-zero -> **the T8150 M2Scaler grammar DIFFERS from 23F77 on BOTH selectors** —
  the leak pairing is T8150-DECODER-BLOCKED until its own contract decodes. Pairing HELD
  (tolerant law); rounds continued; the run died the (b) class (the design target; the
  dirty-boot attribution printed correctly — credited to p8-b200-popwin).
- **THE CHAINING MAP (the user's push, answered)**: the lawful chain = wrap(proven) +
  release-route(uncorroborated = the MISSING LINK, static-decodable) + the oracle field;
  NOT tonight's KRW answer until the release route corroborates. The ANE lanes: 43748 =
  operator-STOPPED (verified-live groom owed), Stage-B pid-borrow = decode-owed; no
  lawful cross-lane mashup (the no-guess law + the variant-C class law).
- **DECODER JOBS LAUNCHED (static)**: (A) the p101 release-route/oracle decode on 24A435
  (the gated dispatcher's userland-reachable caller + the [md+0x98] increment sites +
  the safe corroboration oracle; the 23F77 VAs = priors, re-derive by byte-pattern);
  (B) the T8150 M2Scaler sel-6/sel-8 contract (why 2c2 / why 2bf-64KB; the corrected
  grammar rows). Reports -> ledger + notes; the next taps build on them.

## 2026-11-01 19:5x — the T8150 M2Scaler CONTRACT DECODE landed (agent, 77 static reads) — the 2c2 mystery SOLVED + the leak lane law on the 17
- **sel-6 QueueCreate: the grammar is BYTE-IDENTICAL to 23F77 on T8150** (word0 EXACTLY
  1000 [cmp 0x3e7/0x3e8 cited], in 0xFA8, flags bit0, the 4-stage table @0x80ff4b0) =>
  tonight's 2c2 = **the TAGS verdict**: >=1 of the 1000 sids failed the deep validator's
  live+owned resolution (kext lookup 0xa344130; any miss -> 0x2c2; preamble fail would
  have been **0x2c9** — the value excludes the root leg). NOT a grammar change.
- **sel-8 iosaDiag T8150 law (decode-CONFIRMED)**: in[0] = THE USERLAND BUFFER ADDRESS
  the async dump engine writes into (IOMD base); structureOutput NEVER written (the 64KB
  zeros tonight = BY DESIGN); base = count<=0x100?0x40:0x200, MD = (base+count)*0x7c+0x20;
  **0x2bf = kIOReturnIPCError = ENGINE-ASLEEP** (no such constant in kext TEXEC — the
  commandSleep class), NOT a shape check. Disclosure class SURVIVES on T8150: header
  +0x18 = u64 RAW status token with NO sanitize (a live pointer there = the SLID-law
  candidate); rec+0x18 raw CONDITIONAL on byte[+1]==0; rec+0x20..+0x4c = UNSLIDED KVAs.
- **sel-11 = RAW no-auth engine-member snapshot**: memmove(out, engineMember+0xB8-class
  obj, min(outLen,0x298)) + tail-zeroing; NO gate — **out+0xC = member+0xC verbatim**
  (the p101 oracle's 0x01010101 constant = the member's own bytes, NOT a [md+0x98]
  gate readback — no gate exists in that path). A 0x298B kernel-object read shape.
- **OTHER ROWS**: sel-0/2/3 = 2c7 hard stubs; sel-5 scalar-out; sel-7 = IOMD::withAddress
  Range(in); sel-10 = set_client_property (property id <4 gate); every stub has the
  [x0+0x15c] "must called from user space!" panic guard; 12 rows stride 0x30 @0x80efcd8.
- **p110 v2.8 SHIPPED**: the leak capture now (a) passes OUR buffer as in64 on T8150
  (the CONFIRMED law; the 23F77 echo prior kept on that SKU), (b) classifies OUR buffer
  (signature-2 header, countA/countB, the conditional raw, the KVA fields) instead of
  the untouched structureOutput, (c) names 2bf = engine-asleep honestly, (d) prints the
  QueueCreate 2c2 tags-class law. The pairing's honest next device row: the engine run
  needs LIVE CSC work — the disclosure round needs the engine awake (a real transform
  class queued), else the header stays unsigned and 2bf stands.
- Report file: ~/Desktop/lumina_primitives/notes/t8150_m2scaler_contract_decode_20261101.md

## 2026-11-01 20:1x — the p101 RELEASE-ROUTE decode landed: the 43684 wrap lane CLOSES on 24A435 (byte-cited) — the guard was right
- **THE CHAIN'S TOP-OUT = THE PANIC CLASS, BY BYTES**: the gated dispatcher's release op
  (case w8==5, w1>>24==6, struct>=0x58) = `ldr w8,[md+0x98]; cbz -> bail kr=0 (PHANTOM
  success, NO dec)` — meaning gate-zero = a silent NO-OP, and gate-nonzero = it calls the
  dec FN 0xb3449a4 whose entry check panics ("_dmaReferences underflow @IOMemoryDescriptor
  .cpp:5088") whenever the wrapped dmaref hits 0. **THERE IS NO SILENT DOUBLE-MAP/UAF
  PRIMITIVE IN THESE BYTES** — the wrap-then-release sequence = the device reset, never a
  dangling byte. The page-list-confusion "next design" (sub+0xe0/+0xe8) = DEAD too: its
  precondition (a release-skip leaving the object stale) never fires.
- **p101's device phase-3 refusal = BYTE-CORRECT** (the twin-panic guard held); the lane's
  device product stays the WRAP receipt (65537, kr=0x0, no ceiling at site A 0xb344934 —
  reconfirmed; site B/0x4000-guard-panic also reconfirmed) + these laws.
- **THE SAFE ORACLE EXISTS (decode-CONFIRMED) but its userland row = MISSING**: the gated
  twin's readback op (w1>>24==2, struct>=0x20) copies [md+0x50]->out+0, [md+0x68]->out+8,
  **[md+0x98]->out+0xc**, vtable+0xa8->out+0x18, SAFE (never touches dmaref, never decs).
  The ungated twin's same op does NOT write out+0xc (which explains the p101 census's
  constant 0x01010101 = wrong class/other handler). The twins = vtable slot 18 (vptr+0x90),
  10 gated copies (incl the M2Scaler DCONST 0x10376e8) vs 11 ungated; **zero direct bl and
  zero vptr+0x90 loads anywhere** -> the window protocol's caller = unattributed main-
  kernel plumbing (SUSPECT: generic IOKit map/unmap lifecycle; P086 continues).
- **RECONCILIATION with the M2Scaler-contract decode (the two agents' surface)**: agent A
  reported the UC table MISSING (looked for 24-byte IOExternalMethodDispatch rows; no
  IOUserClientClass personality) — agent B DID decode a 12-row stride-0x30 method table
  @0x80efcd8 (6-qword rows {fn fixup@+8, type@+0x18, in@+0x20, out@+0x28}) inside the
  M2Scaler DCONST. Both consistent: the table EXISTS in the OSObject-method shape, NOT the
  old C shape. And B's sel-11 = the fixed ENGINE-MEMBER snapshot (no gate) — which also
  explains p101's constant. The [md+0x98] readback is NOT reachable via sel-11: the only
  byte-verified route = the window-protocol virtual, still missing its userland row.
- **THE HONEST LANE VERDICT**: 43684-on-24A435 closes as a panic-class receipt lane + a
  SAFE-gate-oracle law; NOT a KRW/write lane. The write-class candidates remaining on the
  17 = the AVE2 DPB cluster (the blob+0x55c law) and the claim-window pairing; the READ
  candidates = the sel-8 T8150 leak law (p110 v2.8, engine-awake required). hasKread stays
  NO by law tonight.

## 2026-11-01 20:2x — the relaxed-rw-protections decode LANDED (rig-boot-chain-only; the SPTM per-PPN table found) + the main-app migration
- **relaxed-rw-protections [mapper+0x99b] = DEAD CODE for us**: writer = the IODART init
  parse only; sole reader = leaf 0x9fac91c (relaxed=1 -> ALWAYS dir code 3); its only static
  caller (fn 0x9fb4590) is referenced by NOTHING cache-wide (zero bl, zero pointer, zero
  adrp) and sits at one AppleT8110DART class-vt(+0xB8) slot (virtual callers unattributable,
  object not user-exposed). DT-provider property only; NO boot-arg/runtime setter.
  **VERDICT: rig-boot-chain-only (DeviceTree-controlled), NOT userland-reachable on any
  decoded path.** The caps field = [+0xa0] (base +0xa4) — the decode DIVERGES from the p148
  brief's +0x131/+0x14 guesses (byte-verified correction; the +0x988 dart-options row).
- **SPTM t8150.release.bin: the string IS LIVE code** — parsed @0xd7320 into [instance+0xc15]
  (neighbor cluster: +0xc0a allow-apf-sid-remap, +0xc0c ignore-secondary, +0xc05
  noncompliant-dead-mappings, +0xc14 avoid-tlbi-in-map, +0xc04 flush-by-dva...); sole
  consumer @0xd3204 in the SPTM-side T8110 DART MAP path: bit==1 -> consult the SPTM
  **per-PPN protection-state table** (16B/PPN @0x2709d000+0x538, byte+2; managed-range
  globals @0x2709e000+0x208/0x210) and when state==1 FORCE the TTE prot bits to
  5|(x26&1)<<3. = the monitor's own mapping-permission policy door — SPTM-internal only
  (signed secure-instance pointers; no userland reach). **NEXT-DECODE LEAD (uncharged):
  the SPTM per-PPN protection-state table = the same state class as the lab's SPTM/UAT
  race lane on this 17.**
- Shared-name diff (strings): true IODART<->SPTM surface = dart-options, relaxed-rw-
  protections, noncompliant-dead-mappings (+real-time, dram-base); the T8110 option cluster
  (allow-mixed-bypass-mode, flush-by-dva, allow-pte-remap...) = AppleT8110DART <-> SPTM
  shared; monitor-only = txm-secure-channel-*, dart-sep, piogw-ps-protection, vm-reserve.
- Report: ~/Desktop/lumina_primitives/notes/iodart_relaxed_rw_decode_20261101.md
- **THE MAIN-APP MIGRATION (the user's ask) SHIPPED (4383371)**: 33 diverged shared files
  synced rig->Exploit (the rig = the dev master in practice), P007Board/P007KreadLane +
  the FULL P100-P148 family (34 probes incl. P110 v2.8) + 34 catalog rows + the
  probeLogFiles map + the T8150 TRACK case. The main IPA = now the full probe set on the
  17 (its honest holds stay: A14/A12X VA-lanes keep their SKU gates; the T8150 laws route
  via the T8150 table + the RocketDoor pins).

## 2026-11-02 — the SPTM t8150 STATE/DATA map landed (agent 2 of 2; bridge-verified against capstone) — THE MONITOR'S CONTRACT, NAMED
- **The kernel→SPTM callgate ABI (decode-CONFIRMED)**: call word {cmd u8@0-7, FunctionID u8@32-39,
  caller_domain u8@48-55}; core table @0x27122350-class (stride 0x18 {auth'd handler, aux, name+perm});
  **44 named handlers** incl: 1=RETYPE, 2=MAP_PAGE, 3/4=MAP/UNMAP_TABLE, 5-11=region ops,
  12/13=CONFIGURE_ROOT/SWITCH_ROOT, 16/17=SIGN/AUTH_USER_POINTER, 20=SLIDE_REGION,
  30-32=HIB, 33=IOFILTER_PROTECTED_WRITE, 41/42=SURT_ALLOC/FREE, 50=OUTPUT_AREA. Dispatch audit fn
  0x270f2fa4; hop state machine 0x2701f808 (0x17 states x 0x0f cmds; per-cpu domain byte +0xb00).
- **THE ONE RUNTIME KERNEL-CONTROLLABLE LEVER = FUNCTIONID_RETYPE (call 1) — hands retype-core
  0x270f988c DIRECT to XNU** (fixup-registered trampoline 0x270fa50c; callgate row 1): writes the
  FTE type byte row[2] = the per-PPN protection state. Validation PANIC-BACKED (bounds <=0x43,
  claimed-current==actual FTE type, the 128-bit transition matrix per policy[actual] @0x2709e240
  stride 0x90, domain-byte match, page-aligned PA; policy[0x00] = all-ones transition mask = the
  universal pivot from a free FTE). FTE row = [0x2709d538] + PPN*16 (managed range 0x2709e208/210,
  PPN=(pa-e208)>>14; hash fallback 0x270ef140). **The retype lever STEERS the T8110 DART map path's
  force-prot csel (0xc15 x policy[+0x30]==1 → csel x23 @0x270d727c) and map_page type gates** — the
  "krw>sptm" tail is now a named, byte-cited hinge: WITH kernel RW, retypes + map ops are the
  monitor-side mapping-permission ladder. WITHOUT KRW: no direct userland reach to any of it.
- Config cluster (+0xbfe..+0xc15, +0xba0/ba8) = DT/ctor-only — no runtime kernel lever (rig-CDT lever
  confirmed as design). FTE init = bootstrap-only; the retype residue list (i-v) recorded for next pass.
- Report: ~/Desktop/lumina_primitives/notes/sptm_t8150_state_map_20261102.md (the arch/ABI agent's
  boot/exception map still pending).

## 2026-11-02 — the SPTM t8150 ARCH/ABI map landed (agent 2/2; bridge cross-checked vs capstone) — the FULL monitor contract, both sides
- **The GENTER ABI on the 17 (decode-CONFIRMED, kernel side)**: tramp va 0xfffffe000ab48018 (unique
  mrs S3_6_c15_c8_0 doorbell in the whole cache) — **x16 = call word, x0-x7 args in-place in/out,
  doorbell-read==0 = done**; gexit va 0xab47b74. Reachability caveat: zero static b/pointer targets
  (runtime-populated tables — the honest negative).
- **SPTM side (CONFIRMED)**: vectors 0x270108000; EL1t sync 0x270a7ca4 = the kernel row; gated enter/
  exit via S3_6_c15_c10_3; SVC 7x7 table 0x2701f4f8 [kind*0x38+sel*8] (PAC ctx 0xc231); state machine
  0x270f253c + 23-state table 0x2701f808; XNU->SPTM action 0x270a62ac blr x1 = the dispatch-resolved
  op handler; sptm_register_dispatch_table 0x270f2000 (domain <=19, entry must lie in PAPT ranges,
  perm bitmask per domain; "Found illegal dispatch entry point" panic class). **The PAC'd data-pointer
  decode law: low24 = fileoff; VA = 0xfffffff027004000 + (p & 0xffffff)** (16/16 verified).
- **Panic law (CONFIRMED)**: illegal dispatch = monitor panic / kernel doorbell spin forever — NO
  return-code path; kernel-supplied data reaching SPTM = genter word (checked) + x0-x7 per-op args
  (per-op validation UNRESOLVED = the named residue) + TXM-stack PA (checked).
- **Kernel-side corrections**: __DATA_SPTM va 0xfffffe000844c000 (0x4c000) = 0 nonzero (boot-filled
  per-cpu mirror); **the old "__sptm_args @0x7ed41c0 stride-0x18" bridge note = NOT REPRODUCIBLE on
  this cache (past EOF) — retired**, do not paste; kernel call-number map = stripped.
- Boot facts: __start 0x270ac388; handshake page at bootargs+0x480 (magic 0x4d545053 "SPTM", v5);
  PAC-key ladder from lit 0x270af988; JOP key = pacga("STACKGRD"); managed range [0x2709e208,0x2709e210)
  reconfirmed; __LATE_CONST NOT fully zero-file (2658 nonzero bytes; boot zeroes only 0x27024000..0x34000).
- Report: ~/Desktop/lumina_primitives/notes/sptm_t8150_arch_map_20261102.md. THE FULL SPTM MAP = the
  standing artifact set: notes/sptm_t8150_{arch,state}_map_20261102.md + scripts/sptm_t8150/.

## 2026-11-06 — the P149-era kernel panic DECODED (panic-full-2026-11-06-192212): the stale-slot UAF = 4-FOR-4, now via P149's prepare-first lane
- `Kernel data abort. pc 0xfffffe004056f188, lr 0xfffffe00406850c4, x0=0x59` under KCS=0x30E40000
  unslides to **pc=0x872B188 / lr=0x88410C4 — byte-identical to the three prior 24A435 panics**
  (the list-init leaf `stp x0,x0,[x0]` through the garbage slot, x0 = 1+0x58, the session-reset
  wrapper). The stale-slot teardown UAF = REPRODUCIBLE 4/4 now — P149's consistent panic = the
  primitive firing, NOT a bug in the lane (the user's p149 consistency = the repro receipt).
- Honest class: the write still carries the slot's own garbage class (1+0x58); conversion needs
  the chosen-content step. The repro = the most deterministic kernel-write event on 24A435.
- The p110 ips 193506 = the client (b) (p110 v2.9's leak-on: QueueCreate 2c2 tags-verdict + the
  t8150 law 2bf engine-asleep — the pairing HELD and the class ran clean 64 rounds; (b) at the end).
- ANECompilerService diskwrites = the established noise class (compiler cache), not a kernel abort.

## 2026-11-06 — the 11-03/11-04 corpus batch DECODED (13 panics): the stale-slot SIG = 9 MORE receipts; 3 MAFs; 2 odd
- **9 more STALE-SLOT SIGNATURE panics** (delta law lr−pc = 0x115F3C, x0 = 0x59 EVERY one:
  072610, 134527, 134831, 134751→134951, panic-base-134736, 100339, 100451, 135503, + the
  192212 from tonight = **THE REPRO CORPUS: 11 byte-identical receipts on 24A435**, different
  slides every boot — the panic is slide-independent and deterministic by construction.
- **3 = the GZ "element modified after free" MAF class** (135503/134910/083959):
  `[data.kalloc.3072] element modified after free (off:0, val:0x000000c00000026a/0x211/0x16a …)`
  = the 43748-fill's record shape captured mid-fire by the GZ guard — the same class that generated
  the operator rule; these = the 11-03 fire-era receipts. The val's payload = the record stream
  {surfaceId-class 0xc0N …} = the fill's write shape, again byte-verified from the kernel side.
- **2 OTHER** (091118/091246/091453 class): pc/lr deltas WILD (garbage lr bands), x0 = userspace-class
  values — DECODE-OWED (full panic strings + the GZ/driver table law needed; do not classify).

## 2026-11-06 — the 13-panic batch ATTRIBUTION CORRECTED (the user's catch — build field per file)
- The **9 stale-slot SIG receipts = ALL the 17** (24A435). The 11-receipt repro corpus = all-17.
- The **3 GZ kalloc.3072 MAFs = the 12 (23F77)** — the 43748-fill record class on the HUNT device
  from this week's fires (the fill landed in FREE elements = the GZ catch; the 10-15 panic's law,
  now re-attested by 3 fresh receipts 135503/134910/083959).
- The **3 wild-delta odd panics = the 12 mini (21D50)** — device-attributed to the mini's
  CS2/libkrw era (path-test-3); decode-owed (the 17.3 banding + the lkrw lane's frames).

## 2026-11-07 — CVE-2026-112554 (the GPT-name OOB read) = a KREAD-CANDIDATE LANE on the 17 (the user's find)
- The device's OWN Cinder tool (Payloads2.swift) builds the crafted GPT (4 x 128B entries, the
  overlong name) and documents the law: **27.0 scan bound = 0x48 (72B); 27.2 tightened to 0x24
  (36B)** => the vector is alive EXACTLY on our 17's build (24A435) and dead on later trains.
- The reach question (the one census owed): the kernel GPT parser runs at DISK-IMAGE ATTACH;
  the parsed partition name = an IOMedia registry property = **userland-readable via the
  IOKit registry** => IF the app can open the DiskImages attach door (the p108 census's
  AppleDiskImages2/KDI UC), the 72B scan overshoot = **36 bytes of kernel-heap bytes
  returned to our app as the "Partition Name"** = the disclosure lane with a chosen input.
- The heap-adjacency design (next build): the kernel allocates the GPT entry array at a
  chosen size (entryCount x entrySize are attacker bytes) — groom the neighbor kalloc with
  pointer-bearing objects, attach, read the name property = the KPTR receipt class. The same
  classifier bands (0xfffffff0/0xfffffe00) apply.
- HONESTY: leak = not kread by itself; this lane = the disclosure primitive + the aim. The
  attach entitlement = the open census row (p108 re-run on the newest build = the tap).

## 2026-11-07 — the Cinder CVE-tool fleet decoded (5 new classes from the device)
- **kern.decmpfs (CVE-2026-113910) = THE GROOM-AWAITING LEAK LANE**: the under-produce read WORKS
  at real scale (xattr=true + 262KB/524KB read-backs, x5 runs) and the classifier says hits=0 —
  i.e. **the read primitive is live but the heap was clean every time: THE GROOM IS THE MISSING
  PIECE, NOT THE PRIMITIVE.** Next build = spray (socket/IOSurface pressure) THEN the under-produce
  read: whatever lands adjacent to the chunk buffers = kernel heap INTO OUR FILE. With the pointer
  classifier = the receipt class.
- **kern.ipc (CVE-2026-112507/112476) = the ipc_port request-table index race** — the oracles fire
  (2 error classes: kr=-300 x12288 + MACH_SEND_INVALID_DEST x3072; converged at ops=512 by the
  resource budget — deliberate). Decode-owed: the full race design (alloc/notify/send/dealloc
  interleave + which reply-table slot the win lands in). Mach port-index races = the classic
  port-confusion class IF the window opens; needs the table-state decode first.
- **kext.gpt (CVE-2026-112554)** = the attach-door census (p108 re-run) remains the open row.
- **aud.immersive (CVE-2026-113907)** = entry probe NEGATIVE (no 'lpcm' deserialization hits on
  this build — the capacity-gap vector does not open here).
- **cm.fdleak.boundary (CVE-2026-112706)** = the honest sandbox map re-attested (13 refused, 1
  openable = .GlobalPreferences; the p116-family law holds).
- HONESTY: all = disclosure/race CANDIDATE classes; hasKread stays NO until a kread32 receipt.

## 2026-11-07 01:00 EST — the 12's post-p130 INSTANT panic (the co-driver receipt, pending the .ips)
- The sequence: the 20:57 p130 = clean in-tap (fence churn 1540 commits, 0 fails) + the 254-fill
  3x pre-marshal rejects (dirty ANE) — then MINUTES LATER the device PANICS; the user rebooted and
  re-fired p130+p073 FRESH (21:00:09) = another INSTANT panic. Two timing receipts within 3 minutes
  on the same co-driver pair.
- The predicted classes (in decode order once the .ips lands): (a) the fence-append corrupt-count
  window = PC in the 0x984fa-0x985cb band (the 2/2 abort class catching the co-driver pair);
  (b) [data.kalloc.3072] MAF = the fill's write into a free element; (c) anything OOL/desc = the
  conversion itself. The 12's fresh-boot p130 = the first FRESH-ANE co-driver fire of the campaign.
- The .ips = sync-pending (not yet in ~/Downloads / CloudDocs at decode time); the moment it
  arrives = the panic_decode pass + the law-row.

## 2026-11-07 (day) — the 12 re-fire receipt + the DeviceOpen pid anomaly, measured
- **p044 v75.2-inlineopen (iPhone 12 / 23F77)**: `request inputs=127 outputs=1 procIdx=0
  sids=363..489 validate=1`; programHandle 0x2dc60b418; `doEvaluateDirectWithModel ok=1`.
  PHASE 5d inline DirectPath DeviceOpen in the SAME process, immediately after the evaluate:
  `[inline] open H11ANEIn type=1 kr=0x0` and `H1xANELoadBalancer type=1 kr=0x0`
  (both open), but `[inline sel0 pid=512] kr=0xe00002f0 (NotFound)`.
- **PHASE 6f foreign sid=170**: useCount 0->0, lockRO=ok, diff=512/16384, now0=af5eaf5e,
  words 0x0000..0x00fc all `00000000 -> 5eaf5eaf` = **the v63 chosen-content write into a
  foreign IOSurface, re-proven** (write primitive; NOT kread/KRW).
- **DeviceOpen pid law — correction to the "aned-only client table" theory**: an earlier run
  got 0xe00002e3 (NoPower = pid FOUND, engine unpowered) for aned pid 342 AND for our own app
  pid 5830; tonight our pid 512 (post-successful-evaluate, same process) = 0xe00002f0
  (NotFound). A table that contained only aned could not have resolved 5830. So the found-vs-
  not-found split is a **lookup/registration law we do not yet have** (candidate: the pid a
  DirectPath DeviceOpen resolves must be the pid that owns an _ANEClient/aned-side registration;
  5830 had run earlier v63 fires, 512 was a fresh process). Open: determine whether a
  pre-registration step exists, and whether the lookup is proc_find or a driver client table.
  Handed to the 24A435 hunt (same handler shape) to settle from the code.
- **NEON witness transport is DEAD on the 12**: every scan = `READ FAIL kr=0x90000003 cnt=0
  alt_kr=0x10000003 alt_cnt=68`, dead_port=32 at every scan. Decode: 0x80000000|0x10000003 =>
  thread_suspend = 0x10000003 = MACH_SEND_INVALID_DEST, alt flavor same. The ports are dead;
  **every historical "NEON clean" scan is a NO-READ**, not evidence. The only successful read
  ever = the 17's wid=4 event. Oracle needs port pinning/restart or the p062 exception
  transport (which is a live-register snapshot, not the PCB oracle).
- **Carrier limit confirmed**: the CoreML carrier cannot deliver >192-record requests on
  23F77 (addchain-254 inference reject is procIdx-independent; passthrough compile fails at
  200 live 16KB inputs). The intended bypass = direct-path sel2 ProgramSendRequest, gated on
  a working DeviceOpen.

## 2026-11-07 (day) — 23F77 ANE UC class map + selector tables (capstone, static)
- Five UC classes built in one init `0x8757c18` (metaclass globals 0xa9de918/940/968/990/9b8):
  `ANEClientInterface`, `H11ANEInUserClient`, `H11ANEInDirectPathClient`,
  `H1xANELoadBalancerClient`, `H1xANELoadBalancerDirectPathClient` (0xe0-byte instances).
- Class -> dispatch table proven by adjacency (slot at meta_vtable-0x20, encoding 0x80415d9d|low32):
  - **H11ANEInUserClient -> table1 0x7cbfa30, 17 sels** (externalMethod 0x875791c, w4=0x11):
    0 DeviceOpen(0x68/0x68) 1 DeviceClose 2 SendRequest(1 sc + 0x948/0x28)
    3 **ProgramCreate**(0x20) 4 ProgramPrepare(0x38/0x38) 5 ProgramUnprepare 6 ProgramDestroy
    7 GetStatus(0/0x20); sels 8..0x10 not yet decoded (p104 census saw 10/11/14/16 ungated).
  - **H11ANEInDirectPathClient -> table2 0x7cbfcd8, 9 sels** (externalMethod 0x8757af0, w4=9):
    0 DeviceOpen 1 DeviceClose 2 SendRequest(async, 1 sc + 0x948/0x28)
    3 OutputSetEnqueue(0x28) 4 InputsReady(0x200c) 5 **MemoryMapRequest**(1 sc + 0x2008, 1 sc out)
    6 MemoryUnMapRequest(0x2008) 7 SessionHintRequest(0x10/0x18) 8 unknown.
  - LB pair mirrors it (table1 0x7cbfa30 slot @0x7cbf2f0, table2 0x7cbfcd8 @0x7cbf978).
- **ProgramCreate (UserClient sel3)** handler 0x87582d0 requires the 0x20 struct to have
  `[+8]==0xd88` and `[+0x18]==0x000ac738`, else `0xe00002c2`; callee 0x8753574 allocates a
  fixed **0xd88** buffer (x0=struct[0], w2=0x20003) -> this is the ANE firmware program load,
  i.e. the daemon/interface path, not an app model. 23F77 create gate callee = `return 1` (open).
- **DeviceOpen registration law (static)**: ANE_DeviceOpen 0x8752524 -> provider vtable+0x558
  = ANE_AddClientForProgram_gated 0x86f3624 -> helper 0x86ef7d0 scans `[self+0xe0]`
  (count vtable+0x90, element vtable+0x118) and matches the **UC object pointer**; failure =
  `0xe00002f0` "Client %p not found". No pid. The 2f0 is a list-membership gate; which selector
  populates that list is still OPEN (candidate: the DirectPath MemoryMapRequest/InputsReady path).
- p153 built: class-ID by sel7 shape (UC 0/0x20 vs DP 0x10/0x18), optional async sel2 reach
  with zero counts (cannot OOB), optional sel5 map / sel3 create; DeviceOpen re-check after.
  PANIC-POSSIBLE only with send/map/create enabled; one tap per force-quit.

## 2026-11-07 (day) — 24A435 corrections from the renamed project (agent memo, verified by decompile)
- **newUserClient 0x8c096f0**: type **1 and 4** -> direct evaluate client (start FUN_8caf080;
  skips `com.apple.ane.iokit-user-access`, dataChaining bit only); **every other type** ->
  program-loading client (start FUN_8caede8; requires the iokit entitlement, else 0xe00002c9).
  The reachable service on 24A435 is **H1xANELoadBalancer** types 1/4 (H11ANEIn service is a
  different IOService whose default newUserClient = 0xe00002c7).
- **DirectPath table 0xfffffe00080554f8, 11 entries (stride 0x28)**:
  0 DeviceOpen, 1 DeviceClose, 2 SendRequest, 3 OutputSetEnqueue, 4 InputsReady,
  5 MemoryMapRequest, 6 MemoryUnMapRequest, 7 SessionHint, 8 ChainingSetActive,
  9 MapMutableWeightsBuffer, 10 UnmapMutableWeightsBuffer.
  Program-loading table 0xfffffe0008055278, 16 entries (ProgramCreate 0x8cb028c, etc.).
  NOTE: P044's "sel4 = ProgramPrepare" is 23F77-only; on 24A435 DirectPath sel4 = InputsReady.
- **DeviceOpen (24A435) 0x8cb004c/body 0x8cb0050**: requires in>=0x88 and out>=0x88, copies
  exactly 0x88, no pid/flags/client-index read, no proc lookup. Tail FUN_8ca817c; AddClient
  failure is **non-fatal when out[0]==0** ("no open programs") -> returns 0. So a zeroed
  0x88/0x88 struct is the correct 17 probe. 0xe00002c2 = size/null output; 0xe00002e2 =
  wrapper state !=2 / DataVault / entitlement; **0xe00002f0 is a send-path error**
  (FUN_8c0b4c4 client-registry miss / FUN_8c11dc8 program-handle miss), not DeviceOpen.
  0xe00002e3 was not found on 24A435 DeviceOpen.
- **Send request 0x8cb0ee4**: 0xd88 structureInput; +0 programHandle (u64), +0x1c procedureId,
  +0x20 totInputBuffers, +0x24.. input ids, +0x420.. symbols, +0x81c totOutputBuffers;
  clamp in+out<=0xff; prewire map object ANE_MapAlloc = 0x10b8 -> max index 254 ends 0x107f,
  trailer to 0x1097 => **255 in-bounds, OOB class patched on 24A435**. Needs a registered
  client AND a valid program handle -> not app-reachable via the direct client.
- **ANE_stageb_pid_borrow 0x8cb33f0**: proc_find + proc_name only; no entitlement query on the
  pid. App pid satisfies it trivially. Effect = transfer a driver memory descriptor's ownership
  to that pid's task (confused-deputy ownership), NOT entitlement bypass, NOT kW.
- **ProgramCreate**: FUN_8d51dd4 = always-allow stub; DataVault 0x8d51434 is the real gate
  (APFS auth 0x80104118 or aned-cache / MobileAsset paths; 4-char suffixes .hwx/.bin).
  argsOutput double-fetch (consumer FUN_8c426b0 re-reads req+0xd8) exists but PopulateProgramOutput
  requires a valid program resource and lives on the entitlement-gated client -> not reachable.
- Probe changes this pass: p151 defaults 0x88/0x88 + pid default 0 (never writes the buffer);
  p150 adds H1xANELoadBalancer and sweeps types 0..5; p153 gained p153_svc /
  p153_send_size (0x948|0xd88) / p153_map_size (0x2008|0x828) / p153_dev_size and uses
  IOConnectCallAsyncMethod with 8 async refs for sel2.

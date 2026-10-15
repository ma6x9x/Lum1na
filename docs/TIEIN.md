# TIEIN.md — Dopamine / Nugget source mining → Lum1na Beta 1 blueprint

Date: 2026-10-14 (evening, post three-device session).
Sources mined: Dopamine 3.0.11 (`~/Library/Mobile Documents/com~apple~CloudDocs/Downloads/Dopamine-3.0.11`),
Nugget 7.4 (`.../Downloads/Nugget-7.4 2` + `/Users/kolby/Downloads/Nugget-main`),
lab notes (`~/Desktop/lumina_primitives`).
Purpose: explain every KRW-era result we logged, and give the concrete ladder that ties
**our own cs2core primitives** into the fastest possible Beta 1 (staging → KRW gate →
inject/install → respring → Sileo/Zebra).

## 1. The Dopamine trust ladder (exact gates, cited)

jbserver runs inside launchd (launchdhook). Every request is `(domain, action)` and
each domain has a `permissionHandler` (`libjailbreak/src/jbserver.c:22-23`). Domains
(`libjailbreak/src/jbserver_domains.h`), handlers in `launchdhook/src/jbserver/jbdomain_*.c`:

| Domain | Gate | Citation |
|---|---|---|
| SYSTEMWIDE | any process, while jailbreak not hidden | `jbdomain_systemwide.c:61-76` |
| PLATFORM | caller has CS_PLATFORMIZED / platform-application / is the Dopamine app | `jbdomain_platform.c:12-14` |
| ROOT | **`audit_token_to_euid(clientToken) == 0`** — nothing else | `jbdomain_root.c:9-12` |
| DOPAMINE | Dopamine app bundle only | `jbdomain_dopamine.c:110` |
| WATCHDOG | watchdogd only | `jbdomain_watchdog.c:48` |

Root-domain actions (`jbclient_xpc.h:28-33`): GET_PHYSRW, SIGN_THREAD, **GET_SYSINFO**,
STEAL_UCRED, SET_MAC_LABEL, TRUSTCACHE_INFO / ADD_CDHASH / CLEAR.

`process_checkin` is SYSTEMWIDE (any process): returns jbroot, **sandbox extensions**
(read + `com.apple.sandbox.executable` on /var/jb, rw on /var/jb/var/mobile —
`jbdomain_systemwide.c:196-206`), `fullyDebugged` for app-bundle processes when the
"markAppsAsDebugged" setting is on, and then applies `cs_allow_invalid(proc,
fullyDebugged)` plus a setuid fix that writes `proc+svuid/svgid` and updates the ucred
(`jbdomain_systemwide.c:213-262`). **This is the exact write recipe Dopamine itself uses
to change identity — proc_svuid/svgid live on proc (our PROC_ROW_D23 svuid 0x3C /
svgid 0x40 match), ucred uid/ruid written after.**

## 2. libkrw root cause (rig symptom, now fully explained)

`Packages/libkrw-provider/src/main.c`: `krw_initializer` wraps everything into
`jbclient_initialize_primitives()`. That function's first line
(`libjailbreak/src/main.c:13-15`):

```c
if (getuid() != 0) return -1;
```

then Root-domain `jbclient_root_get_sysinfo` (fills `kconstant(base)` = what libkrw's
`kbase` returns) and `jbclient_root_get_physrw` (fills kreadbuf/kwritebuf).

So on the rig (Dopamine 18.6.2, our app = mobile uid 501): provider loads, initializer
succeeds, but sysinfo/physrw are refused → kbase rc=0 val=0. **Not a path bug. Not
fixable from userspace. Fixable only by becoming euid 0 — which our own KRW can do
(§4).** On the 12 mini (STOCK): "no provider found" is the honest correct result — no
/var/jb exists. Both logged failures are correct behavior, not defects.

## 3. What our primitives already are, in Dopamine terms

cs2core gives us `kread32/64/buf` + `kwrite32/64/buf` + kbase/slide (board-committed,
self-test gated). In Dopamine's architecture that is exactly the `primitives.c`
layer (`kreadbuf/kwritebuf/kalloc/kcall`) minus kalloc/kcall. Everything Dopamine does
in `kernel.c` is built on those primitives with plain struct math:

- `proc_find(pid)` — walk `ksymbol(allproc)`, compare `proc+pid` (`kernel.c:10-25`,
  `util.c:73-80`). Our P094 kernproc probe is this, minus the symbol table.
- `proc_ucred(proc)` — darwin23: `kread_ptr(proc + proc_ro)` then
  `kread_ptr(proc_ro + ucred)` (`kernel.c:46-54`). Matches our PROC_ROW_D23
  `pro_ro_ucred 0x20`.
- `mac_label_get/set(label, slot)` — **`label + (slot+1)*8`**, plain kwrite64
  (`kernel.c:211-230`). Sandbox unsandbox = clear the Sandbox MAC slot.
- setuid recipe (from process_checkin): `kwrite32(proc + svuid/svgid)` + ucred
  uid/ruid updates + clear P_SUGID on `proc+flag` (`jbdomain_systemwide.c:237-260`).
- **iOS 17 caveat: ucred has a separate RW mirror.** On darwin23,
  `kauth_cred_rw(cred)` = `kread_ptr(cred + koffsetof(ucred, rw))` and uid writes must
  target the mirror (`kernel.c:233-238`). Writing the RO cred would be a no-op/panic
  candidate. Our P095 ucred probe must verify the mirror pointer before any write.
- Trustcache: `jb_trustcache_add_entries` is **pure kwrite** on an existing jb
  trustcache, and `_jb_trustcache_grow` needs `kalloc` (kcall-backed) for a new one
  (`trustcache.c:163-233`). We have no kcall → on Dopamine devices the jb-tc path is
  reachable via Root domain instead; on stock, exec-trust must come from the static
  trustcache (lab notes 12/13/14) or a Ghidra-proven per-SKU static-tc VA.
- `ksymbol(name)` = `gSystemInfo.kernelSymbol.name + slide` — Dopamine ships per-OS
  generated symbol/offset tables matched at runtime (same architecture as our LabOff
  per-SKU tables; their `allproc` is just a row in that table). Our missing 21D50/22G100
  kernproc/allproc rows are the only gap, and P094's invariant validation is the
  proving step.

## 4. Tie-in ladder, device by device

### Rig (iPhone12,1 · Dopamine 18.6.2) — Beta 1 is closest here
1. cs2core establishes KRW (works, proven).
2. P094 kernproc probe → find our own proc (pid lookup) → proc_ro → ucred.
3. P095 verify ucred_rw mirror + uid fields (read-only).
4. Elevate write: svuid/svgid on proc (+ucred_rw uid/ruid) → `getuid()==0` in-app.
5. Now euid==0 → **every Root-domain action unlocks**: `jbclient_root_get_sysinfo`
   fills Dopamine's primitives → libkrw becomes live → `opainject`, `jbctl`, dpkg all
   work as designed. Also `jbclient_process_checkin` still available for sandbox
   extensions/CS_DEBUGGED.
   Our KRW is literally the key that opens Dopamine's Root domain. No entitlement
   changes needed.

### 12 mini (iPhone13,1 · STOCK 21D50 17.3) — our-own-primitives lane
1-3. Same P094/P095 read-only ladder (allproc/kernproc derivation + validation).
4. Elevate write as above (uid0).
5. Unsandbox: clear our ucred MAC-label Sandbox slot (mac_label slot write). Verify by
   successfully reading a path outside the container (e.g. /var/mobile).
6. posix_spawn of staged helpers now permitted by sandbox; remaining wall = AMFI exec
   trust for non-platform binaries. Options, honest ranked:
   a. **static trustcache write** (lab notes 12/13/14) — needs Ghidra-proven static-tc
      VA per SKU; fits our LabOff discipline; pure kwrite.
   b. thread-hijack injection into a running platform process (opainject-style,
      reimplemented on our kwrite) — harder, no exec of new binaries needed.
   c. NOT possible without kernel work: just dpkg -i (dpkg itself needs exec trust).
7. Install: run dpkg from the staged Procursus-lite tree, uicache, respring
   (uid0 killall SpringBoard), post-respring jbroot detection (already in
   Lum1naBootstrap).

### Hunt / iPad (26.x, no Dopamine path)
cs2core correctly gates itself out (patched trains). Untouched by this plan.

## 5. Nugget (host-side) — what is actually reusable

`src/restore/restore.py` — `concat_exploit_file`: restore-domain
`SysContainerDomain-../../../../../../..{base_path}{path}` traversal writes **arbitrary
files anywhere under /var** with controllable owner/group (`FileToRestore(owner:,
group:, mode:)`, default 501:501). `src/tweaks/basic_plist_locations.py` catalogs
known-good targets (/var/Managed Preferences/mobile/*, MobileGestalt.plist,
`/var/db/com.apple.xpc.launchd/disabled.plist` — daemon disabling, etc.).

Lum1na uses (host-driven only — backup restore goes through lockdownd; there is no
on-device equivalent from an app sandbox; do not oversell):
- Pre-stage /var/jb tree (dpkg db, plists, debs) root-owned BEFORE the on-device run,
  shrinking the on-device staging step.
- `disabled.plist` to silence watchdog daemons during respring experiments.
- NOT usable for exec (AMFI checks cdhash, not file mode) and not needed for KRW.

## 6. Stage plan (code steps, in order)

| Stage | Deliverable | State |
|---|---|---|
| A | P094 kernproc probe (read-only, DarkSword LEAD slide + invariant validate: pid==0, proc_ro in 0xfffffff0…, ucred uid==0 for pid 0) | IN FLIGHT (was building when interrupted) |
| B | P095 ucred ladder probe: proc_ro→ucred, ucred_rw mirror presence, uid/ruid/svuid reads for self pid | next |
| C | Elevate write (svuid/svgid + ucred_rw uid/ruid, refcount-safe) + `getuid()==0` console proof | gated on A/B |
| D | Rig: checkin + Root domain + libkrw live + opainject/dpkg via Dopamine | gated on C |
| E | 12 mini: unsandbox (MAC slot) + exec-trust decision (static-tc vs thread-hijack) | gated on C |

Honesty gates unchanged: hasKread only via board.commitSlide; KRW self-test before any
FIRE; one failed tap ≠ CVE closed.

## 7. Key Dopamine file index (what to consult when implementing)

| File | Content |
|---|---|
| `libjailbreak/src/main.c` | primitives init, uid0 gate (§2) |
| `libjailbreak/src/kernel.c` | proc_find/proc_ucred/mac_label/kauth_cred_rw/cs_allow_invalid |
| `libjailbreak/src/util.c` | proc_iterate over allproc |
| `libjailbreak/src/trustcache.c` | jb-tc add (kwrite-only on existing tc) |
| `launchdhook/src/jbserver/jbdomain_systemwide.c` | check-in: sandbox extensions, fullyDebugged, setuid recipe |
| `launchdhook/src/jbserver/jbdomain_root.c` | Root gate = euid 0 |
| `launchdhook/src/boomerang.c` | primitives hand-off to spawned processes (registered ports) |
| `Packages/libkrw-provider/src/main.c` | libkrw = thin jbclient wrapper |
| Nugget `src/restore/restore.py` | /var traversal write (host-side) |
---

## 2026-10-14 addendum — who feeds whom (offsets & primitives)

**Direction matters.** Our borrowed pieces flow Dopamine → Lum1na; our own
pieces do not flow into Dopamine or Nugget today, with ONE real exception
(a libkrw provider, below).

- **Struct offsets**: borrowed from Dopamine `libjailbreak/src/info.c`
  (MIT, (c) Lars Fröder) → our `PROC_ROW` tables. Validated live (rig
  P090 census, 23F77 census 2026-10-14). Nugget has NO kernel offsets —
  it is host-side restore mechanics only.
- **Kernel VAs** (allproc/kernproc/kbase deltas): ours, per-SKU, from our
  own Ghidra passes on the exact decrypted build. Dopamine's ladder is
  per-darwin-version and derives its anchors at runtime on device; our
  build-constant VAs do not upstream into it. 2026-10-14 T8101
  xnu-12377.122.4 derivations (allproc 0xFFFFFFF00A900770, delta
  0x38FC770; kernprocvar 0xFFFFFFF007B6EB30; proc_list_add semantics:
  one-pointer doubly-linked head, le_prev of first == &head) are in
  `LabIntelTab` status GHIDRA and validated by p094 once a lane is live.
- **Primitives**: on a Dopamine-jailbroken device our probes CONSUME
  Dopamine's primitives through the libkrw plugin ABI
  (`P007KreadLane.m`, P090 glue). On stock devices we use OUR OWN
  primitives (cs2core proven on the 12 mini A14 17.3; 26.5 A14 pending).
- **The real feed-back path**: once a KRW primitive of ours passes the
  self-test gate, it can be wrapped as a **libkrw provider dylib**
  (export `krw_initializer`) — every libkrw consumer in the Dopamine
  ecosystem (bootstrap, dpkg/Sileo flows, jbctl) would then use OUR
  primitive. That is the only mechanism by which our primitives feed
  Dopamine's stack. Nugget cannot consume kernel primitives at all
  (host-side); nothing of ours feeds it unless we ship Nugget tweaks.
- **26.5 A14 (23F77) status**: Dopamine has no exploit for this SKU/build
  (basebin covers 26.0-26.0.1 A12/A13 only), so Beta 1 on the hunt device
  stands entirely on OUR lane + the static anchors above. Hunt write
  lanes stay PARKED after panics #1-#3 (see FUTURE.md — all three land in
  AppleH11ANEInterface 0x17401fc wild-write, wedge→harvest family).

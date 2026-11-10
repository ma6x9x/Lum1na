# Lum1na KRW theory — our own map (no CVE required)

Date: 2026-11-09. Scope: the 12 (A14/23F77/26.5), the 17 (T8150/24A435/27.0),
the A12X iPad (23H30/26.7.1). This is a **theory and experiment map**, not a
claim of KRW. `hasKread` flips only on `kread32(kbase) == 0xfeedfacf`.

The CVE lanes are closing: AKS (P161/P104/P057), HID (P162), the ANE prewire
(43748), the AVE2 VT path, and the 23F77 small-kext surfaces (AUC, Multitouch,
JPEG, CoreAnalytics) are all bounded, gated, or patched. What is left is a
composition problem: turn one of our **own** observations into an addressable
kernel read/write without borrowing a CVE's exploit body.

## 1. What we actually have

| Device | Protections | Live primitives | Closed / bounded |
|---|---|---|---|
| **12** A14 23F77 | No SPTM, no MIE/MTE; PPL + CTRR | v63 512 B ANE chosen write into a foreign surface; 43748 record OOB (GZ-attested, element-contained); 86950 in-process glyph OOB; 84607 AVE race; p154 IOSurface listener UAF; p084 pmap-tte PUAF (A14 untested); B6 IOMD retain-wrap (main kernel); p073 desc door; M2Scaler sel11 `0x288` copyout; P098/P063/P097 leaks | 43748 cannot leave its element; v63 is surface-only; AVE2 direct UC `0xe00002e2` and VT clamps; AKS/HID closed |
| **17** T8150 24A435 | SPTM + MIE; DART closed | v63 512 B foreign-surface write (sid 279); 43748 writer statically unbounded but caller-fenced (in+out ≤255); M2Scaler sel8 **permuted-pointer/slide** leak; AVE2 dtor panic-grade / p157 type sweep pending; p073 desc / p130 translation bar; p110 leak unverified | AKS (P161/P104/P057) and HID (P162) exhausted; page tables, text, trustcache, DART SPTM-gated |
| **iPad** A12X 23H30 | PPL only, no SPTM/MIE | P010 QueueCreate copyout; P063 aio heap; post-write testbed | 43748 patched 26.6; 84607 patched 26.7; 86950 patched 26.7.1; p017 FORBIDDEN (GPU wedge); no initial write |
| **11** 22G100 | pre-26 | CS2 baseline (one spray per boot) | not our chain |
| **12 mini** 21D50 | Dopamine | libkrw baseline (KRW-PASS) | not a novel chain |

Two observations drive the theories below:

1. The **12 has no SPTM and no MTE**. Any kernel data write lands; PPL/CTRR
   only guard text, page tables, trustcache and `pmap_cs`. `proc`, `ucred`,
   `task`, ports and most heap objects are ordinary RW data.
2. The **17's SPTM** mediates page tables, DART/SMMU, trustcache and retype —
   but **not** a `copyin`/`copyout` into an ordinary data object. A data-only
   read/write is exactly the space SPTM leaves open. MIE only checks the tag
   of the destination.

## 2. Theory A — Descriptor-Port Confusion (DPC)

**One line:** a Mach message descriptor is a 16-byte union; if a
client-controlled record changes a **port** descriptor into an **OOL**
descriptor after validation, the kernel's OOL copy engine uses the port's
kernel pointer as the OOL address — a kernel read/write of the port object,
with no page-table or DART involvement.

**Why it is ours.** It is a composition of our own p073 desc-door layout,
p113 DescForge control, and the IOSurface/M2Scaler KVA leaks. It is not a CVE
body; it is a descriptor-union type confusion.

**Known shape (p073):** received descriptors are
`{ u32 name; u32 pad; u16 type@8; u16 disp@10 }`. The OOL union is
`{ u64 address; u32 size; u8 deallocate; u8 copy; u16 pad }`. A port
descriptor's first eight bytes become the OOL **address**; the type/disp
fields become the OOL **size/copy** fields. In a kernel-resident message the
first eight bytes are the kernel **port pointer**, not a user port name — that
is the address the copy engine would use.

**Chain (to be proven, not assumed):**

1. **Create a port we own.** Send a message with a descriptor array that
   includes a port descriptor. Smash one descriptor's `type` to OOL (the
   p073 "record smash"; a record overwrite or a narrow race after the kernel
   validated the port).
2. **Read oracle.** Let the kernel copy an OOL descriptor from the port
   object to a user buffer. If the buffer contains `ipc_port` fields
   (refcounts, `ip_kobject`, `ip_receiver`, `ip_messages`, lock words), the
   confusion is real and the address is the port pointer.
3. **Write oracle.** Use the send-side OOL direction with a 16-byte marker
   and a controlled size; write into our own port object. Detect the write
   by a second read or a port property change. No arbitrary target yet.
4. **Fake kobject.** Overwrite `ip_kobject` (or `ip_receiver`) with a pointer
   to a fake object placed in a kernel-mapped user buffer whose KVA we leak
   (P098 IOSurface KVA, M2Scaler sel8 record buffer, or an ANE surface
   backing). Trigger a message to the port so `ipc_kobject_server` dispatches
   through the fake object's method table.
5. **Gadget → KRW.** The fake method calls a kernel gadget with controlled
   arguments (`copyin`/`copyout`/`memcpy`/`ldr`/`str`, or a stack pivot). Use
   it for `kread32(kbase)` and for `proc`/`ucred`/`task` data edits.

**What we must prove (open):**

- the type smash survives the kernel's validation and is observed by the
  copy engine (the p073 oracle is the starting point, not proof);
- the OOL address really is the kernel port pointer (not re-translated to a
  user name);
- the size/copy bytes are controllable enough for a bounded write, and the
  direction (send vs receive) selects write vs read;
- the kobject dispatch path and the port-object field offsets per build
  (`ipc_port` layout is not yet decoded here);
- MTE on the 17: the port object's granules must share a tag for an in-object
  write; a cross-tag linear copy faults. On the 12 there is no MTE, so this
  is the primary host.

**Risk:** PANIC-POSSIBLE (descriptor/kmsg corruption). One tap per
force-quit; no blind selector sweeps; no remaining-fire.

**Result (P163 v1, 17/24A435, 2026-11-09):** the control (all port
descriptors) sends/recvs cleanly with type=0. Every forge case also returns
`send/recv kr=0`, but the received descriptor is **normalized to
`name=0, type=0, disp=0`**. The userland type word is validated/normalized;
it never reaches the OOL copy engine. The translation bar is **not crossed**
from userland. A kernel write to the kernel-resident descriptor is required
(the p073 record smash or a kw provider); a userland forge alone cannot
produce the OOL-address confusion.

### 2.1 P073 desc-smash on the 12 (design)

This is the 12's version of the DPC: use the ANE prewire record stream to
overwrite a **port descriptor** in the same kmsg body, changing its type word
from 0 (port) to 1 (OOL) **after** the userland validator has run. No userland
type forge (P163) and no kw provider.

**Layout (p073 v7g, measured):** 16 port descriptors extend the desc block to
`body+0xC4`; the OOB record stream lands at `body+0x64..0xC4` and overwrites
descs 6..15. A 43748 fill record is `{sid u32, flags u32, tail 0x1000000001}`
at 16-byte stride, 1:1 with the 16-byte kernel descriptor. The record's
`tail` at +8 writes `{type u16 = 0x0001, disp u16 = 0x0000}` — a clean
port desc is `{type=0, disp=0x11}`, so the smashed desc becomes OOL. The
record's `sid` at +0 and `flags` at +4 overwrite the descriptor's first
eight bytes.

**The blocker:** for an OOL desc the first eight bytes are the **address**.
The smashed address is `sid | (flags << 32)`. In the 43748 fill the `flags`
is the **record index**, and at the desc block that index is **6..15**. So
the OOL address is a **user VA** (`0x6..0xF_<sid>`), not the kernel port
pointer. The record also overwrites the port pointer, so the original
kernel address is gone. On the 12 the record count is capped below 0x100;
the index can never be the kernel high half (0xfffffe00 / 0xfffffff0).

**Why p073 v9's current check is not proof:** `p073_ool_probe` computes
`addr = name | pad<<32` and calls `p073_vmread(addr)` **from userland**.
A userland `vm_read` cannot read a kernel VA; it can read the user VA above.
If that user VA is mapped and contains kernel-looking qwords, the
`kernelRange=YES` line is a **false positive** (our own page), not a kread.
The real copy, if the kernel processed an OOL desc, is in the **received
message body** — scan the received body, not `vmread(addr)`.

**Two paths to a real kernel-address OOL read:**

1. **Control the record `flags`.** Find a prewire record write whose +4 u32
   is user-controlled (the `symbols`/`sid`/out-record paths) rather than the
   rec_idx. Then set `flags = 0xfffffe00` (or `0xfffffff0`) and `sid` to the
   low 32 bits of a target kernel VA. The OOL address becomes a kernel
   address; the receive-side body contains kernel data. This is the clean
   DPC read and the 12 has no SPTM/MTE to stop the copy.
2. **Partial type write.** A write of only the `tail` at `desc+8` (or any
   4-byte write to the type word) preserves the descriptor's first eight
   bytes — the **kernel port pointer**. The OOL address is then the port
   object; the OOL copy leaks the `ipc_port` and adjacent data. The current
   fill record is 16 bytes, so it overwrites the pointer; a 4-byte/8-byte
   write path is required.

**Experiments (12/23F77, one tap per boot):**

- **E-desc-1 (body scan):** after a forged OOL desc is received, scan the
  **received message body** for kernel-range qwords and for port-object
  patterns; do not use `vmread(addr)` as the read. This distinguishes a real
  kernel copy from a user-address copy.
- **E-desc-2 (flags control):** audit the prewire record writes for a +4 u32
  that is user-controlled. If found, set it to `0xfffffe00`, `sid` to the
  low32 of a known kernel VA (e.g., a port pointer from a P098/M2Scaler
  leak), and check the body.
- **E-desc-3 (partial type write):** find a 4-byte or 8-byte write at
  `desc+8` that preserves `desc+0..7`; the port pointer then becomes the OOL
  address.

**Static audit (23F77/24A435):** the prewire writer is a **16-byte record**
write: `+0 = sids[i]` (user), `+4 = record index`, `+8 = fixed tail`
(`0x1000000001` in / `0x200000001` out). The only user-controlled u32 is
`+0`; `+4` is the loop index and the tail is fixed. There is no 4/8-byte
type-only write at `+8`. So **E-desc-2 and E-desc-3 are static negatives in
the current writer**; the only live experiment is **E-desc-1** (the v15
body/copy scan). If it reports `srcKernel=0`, the desc-smash is a type-forge
bar, not a kread. A kread needs a different kernel write primitive or a
descriptor whose first eight bytes survive.

**Verdict for now:** the p073 desc-smash on the 12 is a **type-forge bar**,
not a kread, until E-desc-2 or E-desc-3 lands. The p073 v9 `kernelRange`
line is not sufficient evidence. This is the honest design to add to the
map; do not claim a read from it.

## 3. Theory B — PTE Reclaim (p084)

**One line:** the 65,537-map `pt_desc` wrap leaves a dangling PTE; if the
freed pmap page is reclaimed as a **page table**, the old user VA maps that
page table and the user can edit PTEs → arbitrary physical read/write.

**Why it is ours.** It extends our p084 probe (the published pmap-tte
recipe, not a CVE) with a page-table reclaim groom and a PTE oracle. It does
not depend on any SPTM bypass; it targets the MMU, not SPTM-managed metadata.

**Chain:**

1. **Dangle.** Run the p084 recipe: 65,537 `MAP_SHARED` maps wrap the 16-bit
   `pt_desc` count; one unmap frees a pmap page while a PTE still references
   it. The probe's existing oracle confirms the dangling PTE.
2. **Reclaim.** Spray page tables with large sparse `mmap`/`mach_vm_allocate`
   regions so the freed page is reused as a PTE page. The old VA still maps
   the same physical page; if the page is now a PTE page, the old VA exposes
   the PTE array.
3. **PTE oracle.** Write a marker PTE for a known user page, then read the old
   VA. If the marker appears, the page is a page table we control. If the old
   VA faults or is remapped, the reclaim failed (the A12X result).
4. **Physical scan.** Point a PTE at candidate physical pages, scan for the
   kernel Mach-O magic `0xfeedfacf`, and derive `kbase` from the found header.
5. **Target.** Map the `proc`/`ucred` physical page, edit, and verify with
   `kread32(kbase) == 0xfeedfacf`.

**What we must prove (open):**

- A14 reclaim: the A12X recipe executed exactly but found no reclaim; the
  12's A14 may differ, and the 12 has no MTE to trip;
- PPL/CTRR behavior on a page that is reused as a page table while an old
  user PTE still maps it (does the old PTE keep user RW permissions?);
- the physical base of the kernel on the 12 and the PA↔VA relationship
  (physmap) for the scan;
- 16 KB page geometry and the `pt_desc` wrap count on A14.

**Risk:** high; PANIC-POSSIBLE; one tap per fresh boot; p017 remains
FORBIDDEN on the iPad. Do not remaining-fire.

**Result (P084 v7, 12/23F77, 2026-11-09):** the D2 2,048-surface IOSurface
spray found `signature_surfaces=0` and `weak_surfaces=0`; C3 was 0/0 and
the 60s watch 0. The free/reclaim did not occur on A14 with this recipe.
The 17's premise is structurally dead (`cpt_mapcnt` has no silent u16
wrap), and the 12 matches the A12X negative. **P084 is closed**; do not
spend more boots on the pmap-tte lane.

## 4. Theory C — bounded write lanes (stage-2 only)

These are useful only **after** an address/read lane exists; they are not
KRW on their own.

- **v63 ANE 512 B chosen write:** writes a foreign IOSurface backing. It is
  a cross-process/surface write, not kernel memory. Target a privileged
  surface consumer only if a kernel-consumed surface is found.
- **43748 record OOB:** GZ-contained on the 12; caller-fenced (≤255) on the
  17. Self-corruption only; do not remaining-fire.
- **AVE2 signed writer (17, p157):** if a direct UC type opens, a negative SPS
  count underwrites the AVE2 buffer. It is a same-zone heap write; combine
  with the sel8 slide only if a same-zone victim is found.
- **B6 IOMD retain-wrap:** refcount wrap → premature free → UAF; needs the
  real UC op channel (P086 hold). Not a direct write.
- **p154 listener UAF:** type-isolated; DoS/type-confusion, no write path.

## 5. Device map

| Device | Best theory | Leak / address | Write | Target | Confidence | Next |
|---|---|---|---|---|---|---|
| **12** 23F77 | **A: DPC via p073 record smash** (primary); C: AVE2/B6/86950 (stage-2 only); **B: p084 CLOSED** | M2Scaler sel11 `0x288` copyout; P098 IOSurface KVA; P063 aio; P097 | port-object copy (A, needs a kernel descriptor smash); 43748/v63 bounded (C) | `kernproc`/`allproc`/`ucred` | A userland forge normalized; kernel smash untested; B closed (D2 0/0) | p073 desc smash / kw path; 86950/84607; B6/P086 |
| **17** 24A435 | **A: DPC (needs kernel smash)**; C: AVE2 p157 | M2Scaler sel8 **permuted** pointers; p110 unverified | port-object copy (A); AVE2 heap OOB (C) | data-only `task`/`ucred`; same-tag | userland forge normalized; p130 translation bar; C untested | p073 desc smash; p157 type sweep |
| **12/17 (pre-KRW)** | **D: P116 TOCTOU → daemon deputy** | out-of-container read (P116), group map | out-of-container write to a **mobile-writable daemon cache** (P116 rw) | `aned` / `videocodecd` / `_analyticsd` | unproven; needs a daemon-read cache | P116 v2 path/dir/rw; enumerate `/var/mobile/Library/Caches` |
| **iPad** 23H30 | B closed (p084 dead); post-write lab only | P010/P063 | none confirmed | — | low | do not tap p017; only after a chain exists |
| **11** 22G100 | CS2 baseline | — | — | — | existing | not novel |
| **12 mini** 21D50 | libkrw baseline | — | — | — | KRW-PASS | not novel |

## 6. Experiment order

1. **12 — P084 v7**: closed. D2 2,048 surfaces found 0 strong / 0 weak; C3 and
   the 60s watch found nothing. The free/reclaim did not occur on A14. No
   further pmap-tte boots.
2. **12/17 — DPC**: P163 v1 userland forge is **normalized** to a null port.
   The next step is a **kernel write to the kernel-resident descriptor**
   (p073 record smash or a kw provider), not another userland type word.
3. **17 — p157 type sweep**: if a direct AVE2 UC type opens, build the
   Prepare negative-SPS blob; it is a stage-2 heap write, not KRW alone.
4. **12 — B6/P086** and **p154** only as fallbacks; they need a separate
   UAF/refcount groom.
5. Every positive must end in `kread32(kbase) == 0xfeedfacf`. A leak, a slide,
   a surface write, or a panic is not KRW.

## 7. Why this is a new chain, not a CVE copy

- **DPC** is a descriptor-union type confusion built from our p073/p113
  observations and our KVA leaks; no CVE is named in the chain.
- **PTE reclaim** is the p084 recipe (a public pmap design bug, not a CVE)
  extended with our own page-table reclaim and PTE oracle.
- The CVE lanes (43748, 43724, 112515, 112477, 84607, 86950) are treated as
  **evidence and tooling**, not as the exploit body.

## 8. Honesty bar

- Kernel read/write is not obtained until `kread32(kbase) == 0xfeedfacf`.
- A leak is not a read; a slide is not an address; a surface write is not a
  kernel write; a panic is not KRW.
- One TAP per force-quit. PANIC-POSSIBLE badges mandatory. No panic-corpus
  pushes; .ips files stay local. No credentials or tokens logged or pushed.
- The 12/23F77 is the best full-chain host because it has no SPTM and no
  MTE; the 17 is the best data-only host because SPTM leaves ordinary
  copies alone. The iPad is a post-write lab, not an initial-write target.

## 9. Built (2026-11-09)

- **P084 v7** (`P084PmapTtePUA`, log `p084_pmap_tte_puaf_log.txt`): **closed**.
  The D2 2,048-surface IOSurface spray found `signature_surfaces=0` and
  `weak_surfaces=0` on the 12; C3/Phase E also 0. The free/reclaim did not
  occur on A14, and T8150 is structurally dead. No further pmap-tte boots.
- **P163 v1** (`P163DescOOLOracle`, log `p163_desc_ool_log.txt`): the DPC
  userland oracle. Control works (16 port descs, type=0); every forge case
  sends/recvs 0 but is **normalized to `name=0, type=0, disp=0`**. The
  userland type word never reaches the OOL copy engine. The next DPC step is
  a kernel write to the kernel-resident descriptor (p073 record smash or a
  kw provider).

## 10. Theory D — TOCTOU daemon deputy (Chollima-style)

**The idea:** stop trying to reach the kernel wall from the sandboxed app.
Use P116's deterministic sandbox-extension TOCTOU to **read and write
out-of-container files**, then borrow a **privileged daemon's position** to
reach the AVE2/ANE/CoreML lane that the app itself cannot open (AVE2 direct
UC is `0xe00002e2`; the ANE client validate fences P044/P073). This is the
Chollima shape: userland sandbox → daemon → kernel-adjacent entitlement.

**Primitive (P116 v2):**

- `Documents/p116_path.txt` — one out-of-container read.
- `Documents/p116_dir.txt` — directory listing (128 entries).
- `Documents/p116_rw_path.txt` — read-write probe, restricted to `/var/mobile`
  (default `/var/mobile/Library/Caches/p116_rw_probe.txt`).
- Deterministic, no race; tokens never logged; default read-only. The bug
  bypasses the **sandbox path check**, not Unix uid/gid. The app remains
  `mobile:mobile` (501); the VFS still enforces permissions.

**Second key (if the signature carries a real app group):** P160 v2's
class-7 door is the same class of file access with a **kernel-minted token**
instead of the issue/consume TOCTOU. iLoader/paid/ESign can put a real group
in both the entitlement and the profile; p160 logs `[ent]`/`[profile]` with the
group, and its v2b knobs (`p160_path.txt`, `p160_dir.txt`,
`p160_write_target.txt`; write opt-in under `/var/mobile`) read/list/write
outside the container. **Open the part symlink** (`group/Library/Caches`) after
the token, not the target path directly — the target-direct open is `EPERM`;
v2b does this. The group is the **key**, not kernel access: `kread32` still
gates hasKread.

**Who the app is (from `/etc/group`):** `mobile` primary 501; the groups that
name `mobile` are `_analyticsusers` (250), `systemusers` (299) and
`_accessory_mobile_share` (286). `wheel`/`admin`, `_securityd` (64),
`_trustd` (282), `_coreml` (280) and `_driverkit` (270) do **not** include
`mobile`. Check the actual supplementary groups with `getgroups()`; the group
DB is a target map, not a privilege grant. `/etc/group` itself is world-readable,
so reading it only proves the sandbox bypass.

**Daemon-deputy targets (what better position buys):**

| Daemon / class | Why it matters | Mobile-writable surface to look for |
|---|---|---|
| `aned` / `_coreml` | ANE entitlement; can open the direct ANE client that the app cannot. A model/cache it loads could reach the prewire with a different client validate. | `/var/mobile/Library/Caches/` ANE/CoreML model caches; model files in app/group containers |
| `videocodecd` / `mediaserverd` | AVE2/VideoToolbox entitlement; the app's direct AVE2 UC is `2e2`. The signed writer is the 27.x lane (p149/p157). | media caches, thumbnails, playlists, `/var/mobile/Media/` |
| `_analyticsd` | `_analyticsusers` includes mobile; parses crash/analytics data. A parser bug in the daemon is a userland privilege gain. | `/var/mobile/Library/Logs/`, analytics caches, `CrashReporter` |
| `cfprefsd` | Preferences plumbing; ownership/domain checks make it lower value. | `/var/mobile/Library/Preferences/` (cfprefsd may overwrite) |
| `_securityd` / `_trustd` | High value, but their data is not mobile-writable. Do not target. | — |

**The chain to try:**

1. **Enumerate** with `p116_dir.txt` over `/var/mobile/Library/Caches`,
   `/var/mobile/Library/Logs`, `/var/mobile/Media`, and the app/group
   containers. Read candidates with `p116_path.txt`; look for a file a daemon
   reads **directly** (not cfprefsd) and parses (cache/plist/model/media).
2. **Write a copy first.** Use `p116_rw_path.txt` on a **new** file under
   `/var/mobile/Library/Caches/`; never overwrite a daemon's live cache on the
   first run. If the write succeeds, the rw TOCTOU class is live.
3. **Deputy confirmation:** put the poison on the path the daemon reads, trigger
   the daemon's read (relaunch/foreground/notification, not a kill loop), and
   look for a behavior change in logs/telemetry. This is the userland
   privilege/deputy proof.
4. **Kernel-adjacent use:** if the deputy is an ANE/media daemon, use the
   existing AVE2 signed-writer (`p149`/`p157`) or ANE prewire (`P044`/`P073`)
   lane **through the daemon's entitlement position**. The app's own wall is
   bypassed because the daemon, not the app, opens the UC.
5. **Verify** only with `kread32(kbase) == 0xfeedfacf`.

**What must be proven / may fail:**

- a daemon must read a **mobile-writable** file **directly** and parse it;
  many caches are root/`_daemon`-owned, SQLite/WAL, signed, or rewritten by
  the daemon on launch;
- the daemon may validate a signature/checksum or ignore the file;
- the write may be denied by the sandbox extension class or the VFS;
- poisoning a live daemon cache can brick services or boot-loop. Use copies,
  non-critical daemons, one tap per boot; never `/etc`, `/System`, launchd,
  keychain, `_securityd` or `_trustd`.

**Why it is worth trying:** P116 is deterministic, live on 24B119, and needs
no app group. It is the only current primitive that gives out-of-container
**write** without a kernel bug. If a single privileged daemon reads one
mobile-writable cache, the app's AVE2/ANE wall becomes irrelevant — the
daemon carries the entitlement. That is exactly the Chollima "better
position" move, and it is a **separate bug hunt**, not a KRW claim by itself.


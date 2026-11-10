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


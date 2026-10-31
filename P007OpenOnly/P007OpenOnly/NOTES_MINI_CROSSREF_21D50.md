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
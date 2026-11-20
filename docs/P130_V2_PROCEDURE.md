# 3072 clean-write experiment (P130 v2) — device procedure

## Build
CI green on `__LATEST__` (P130 v2 = `p130-fencesecondtable-v2` in the debug tree).
Install the new `Lum1na-Debug-unsigned-ipa`.

## Device
iPhone 12 (23F77). **Fresh boot. One tap. PANIC-POSSIBLE.**

## Steps
1. Fresh boot, open Lum1na-Debug.
2. Tap **p130** (the FUSION probe — now v2 with the pre-stage).
3. If it SURVIVES: paste back `p130_fencesecondtable_log.txt`.
4. If it panics: pull the .ips (`idevicecrashreport -e`) — the panic's
   element dump + the `rc` address are the receipt.

## What the v2 pre-stage does (in order, before the fence churn)

```
[v2-GROW]     200 surfaces created + held — the registry map crosses the
              192-cap boundary (192 × 16 = 3072) and the growth path
              kfree_data's the old 3072 element

[v2-RECLAIM]  the freed slot raced by 3072-class allocations:
              (a) the NECP long-string attempt (kalloc strlen+1 — if the
                  kernel caps under 255 the errno row says so)
              (b) the OSData property attempt (a 3072-byte CFData on the
                  IOSurfaceRoot service → the OSData buffer family)

[v2-WRITE]    the fencer's blit churn continues on held sids → the racing
              writer (the flagged single-store instance from the decode)
              writes {sid|metric,(1,1)} into the slot
```

## What the receipt means

| Outcome | Meaning |
|---|---|
| **SURVIVED + a reclaim channel ACCEPTED** | the write landed in a **live** reclaimed object — the zone scrubber is blind to allocated elements — **the silent write, the clean-kwrite primitive's first receipt** |
| SURVIVED + both reclaim channels rejected | the churn never crossed the boundary or the slot wasn't hit — the channel-cap rows tell which (the NECP 255 law? the property gate?) |
| **Panic: element modified after free** | the free won the race — the external reclaim didn't claim in the ms window. The panic's element dump + `rc` address are still the per-boot map. Retry next fresh boot |
| Panic: the fence-append abort (0x984fcc8) | the write landed in another consumer's array (Rank 2 — the crash lane). Also a receipt — the write is landing, just not in a live reclaim |

## Honesty
hasKread stays NO until `kread32(kbase) == 0xfeedfacf`. A SURVIVED row is a
primitive receipt, not the gate. The 3/3 panics to date are the *failure*
mode (the scrubber catching a freed-element write) — v2 exists to make the
write land in a **live** object where the scrubber can't see it.

— findings: `ios-xnu-hunt/findings/2026-11-20_3072_activity_write_recipe.md`

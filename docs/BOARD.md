# Lum1na kernel board

File on device: **Documents/lum1na_board.json**

Dopamine 3.0.10 keeps a `system_info` blob (slide, symbols, physrw, kcall) *after* kreadbuf. Lum1na does not copy that KRW. This board is the A14/PPL-shaped store:

- identity (machine, 23F77, LabOff tag)
- unslid pins (fn4, wvek, AVE Close, ANE CheckandPrewire)
- leak list `{va, kind, source, time}` — heap vs text
- `hasKread` / `hasKwrite` stay false until a kread of a **known kernel string** works
- `commitSlide` refuses heap−staticBase

After kread (HOLD until then): AMFI loadTrustCache, pmap_cs_allow_invalid, userspace reboot. See All stages → **afterkread**.

Do not copy ClearSword, kfd, physrw.c, or Fugu14 kcall. Those are A12/A13 26.0.0.1.

## Auto vs tap

You do **not** tap “Kernel board JSON” to collect pointers. That button only **prints** the file.

| What | When | Need to tap Board? |
| --- | --- | --- |
| machine, 23F77, `pins.*` | App launch (`refreshIdentity` → `LabOff()`) | No |
| `leaks[]` | Only if the **probe** calls `recordHeapLeak` / `recordCandidate` | No — tap the **probe** |
| `kslide` / `hasKread` | Never auto. `commitSlide` refuses heap−staticBase | N/A until real kread |

Wired today: **aio84530** (`sdata`), **cskrw** (race hit). Everyone else (p009, p010, p017, p056, p057, …) logs to the console / `p0xx_*_log.txt` only.

## Hook a new probe

```objc
#import "Lum1naBoard.h"

// kernel-range VA from this tap:
[[Lum1naBoard shared] recordHeapLeak:ptr source:@"p0xx"];
// or: recordCandidate:ptr kind:@"text" source:@"p0xx"];  // only if it is kernel TEXT
```

Do not call `commitSlide` with `ptr - 0xFFFFFFF007004000`. After kread of a known kernel string, `Lum1naAfterKread` is the next slot (`hasKread` still false until then).

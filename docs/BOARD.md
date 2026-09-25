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

Drop unsigned tweak dylibs here (copied into Documents/tweaks on AfterKread tap).

They will not load until:

  1. KRW self-test: kread32(kbase) == MH_MAGIC_64
  2. AMFI loadTrustCache sel 2/7 and pmap_cs_allow_invalid
  3. opainject of launchdhook, then respring (jbctl / backboardd)

Sileo is the first package manager, Zebra the second (Resources/pkgman).
This folder is inventory, not injection proof.

ElleKit (CydiaSubstrate fallback inside Resources/basebin/basebin.tar) is
the intended loader after those steps. Credit: Dopamine 3.0.10 / Relaxin 0.5.4.

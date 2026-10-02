Drop unsigned tweak dylibs here (copied into Documents/tweaks on AfterKread tap).

They will not load until hasKread, AMFI loadTrustCache sel 2/7, and
pmap_cs_allow_invalid. This folder is inventory, not injection proof.

ElleKit (CydiaSubstrate fallback inside Resources/basebin/basebin.tar) is
the intended loader after those steps. Credit: Dopamine 3.0.10 / Relaxin 0.5.4.

Sileo first, Zebra second.

These are the same .deb files Dopamine 3.0.10 ships in its app bundle
(sileo.deb, zebra.deb). AfterKread copies them into Documents/pkgman on
every tap. dpkg -i does not run until:

  1. board.commitSlide (kread32(kbase) == MH_MAGIC_64)
  2. AMFI loadTrustCache sel 2/7 of basebin.tc
  3. Procursus bootstrap provides /var/jb/usr/bin/dpkg

bootstrap_*.tar.zst is not copied (kfd/ClearSword/physrw stay out too).
Without dpkg the debs stay staged. Files present ≠ Sileo installed.

Credit: Sileo Team (LICENSE_Sileo.md), Zebra / Wilson (LICENSE_Zebra.md),
Dopamine 3.0.10 bundling (opa334, MIT).

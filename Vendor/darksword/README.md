# Vendor/darksword — the vendored socket-lane KRW ("darksword-kexploit-fun")

Copied **verbatim** from git.jbjflab.top/admin/filza27.2 v27.2.0
(`kexploit/`, `kpf/`). Author credit: **seo**, "darksword-kexploit-fun"
(created 2026-03-24). Lab-internal origin on our own git server;
operator-directed verbatim borrowing 2026-11-11.

- No upstream LICENSE file exists. Treat as lab-internal; do not
  redistribute outside this repository without the owner's call.
- The socket lane family matches our ClearSword/CS2 lane
  (inpcb/icmp6filt/ipi_zone/so_usecount). The vendored offsets.m carries
  per-train hex-pattern derivation rules for iOS 17.x-26.x, incl. a
  26.x kbase-magic check (`0xCC0000002`) and receipt on iPhone14,6 iOS 26.0.
- Entry point used by Lum1na: `int kexploit_opa334(void)`; after success the
  `g_kernel_base`/`g_kernel_slide` globals hold the live slide; the krw
  family (`kreadbuf/kwritebuf/kread64/kwrite64/...`) in KrW works on the
  live phys lane.
- Lum1na integration (our code, not theirs): `Exploit/DarkswordBridge.h`
  externs + `Kernel/Lum1naDarkswordLane.{h,m}` lane + the KRWBridge
  `EstablishFromDarksword` path (slide recomputed against OUR LabStaticBase —
  their hardcoded 0xfffffff007004000 is the A14 band only).

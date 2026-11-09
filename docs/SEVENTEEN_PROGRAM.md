# THE 17 PROGRAM — the first Lum1na jailbreak attempt (24A435 / T8150)

Written 2026-11-01 (the night's pins, all committed; the honest board law
unchanged: hasKread flips ONLY on kread32(kbase)==0xfeedfacf in P007Board).

## The three live pieces (in order)

1. **The reproducible AVE2 kernel write (5+, same PC, our own tap)**
   - Trigger: p142 v4 (the stage9 mode): EncoderUsage=1, RCMode refused
     (-12900 on this build), RealTime=FALSE, NumberOfTemporalLayers=raw,
     HEVC 1280x720, then encode.
   - Receipt: bug_type-210, pc AVE2 __TEXT_EXEC +0x5A78 (unslid 0x8723188
     via the .ips's Kernel-slide 0x34360000), LR kext-internal,
     far = 0x59 + (N-16463)<<32 = the PoC's formula (CVE-2026-112705's
     writer cluster, credited MMdAS/Calif), esr = kernel WRITE.
   - The userland VT trap (VideoToolbox+0x25ef28 SIGTRAP) = the feature
     path's guard; the OFFLINE path bypasses it (the stage9 differential).
   - Site decode: the pc = the alloc/oslog fail path; the faulting write =
     the count-scaled fill after an alloc-size computed from the INTERNAL
     raw count (the readback=1 clamp = VT's store law; the internal count
     survives = the knob that reaches the kext).
2. **The Rocket submit door (statically CLOSED; the connect live)**
   - IOGPU t1 connect = kr=0 (p143 row; t0 = 2c7 exclusivity).
   - The owner gate: sel-0x24 reads [uc+0x120] first; zeros = 2c2 (the
     reply-class census).
   - The remaining decode = THE OWNER SELECTOR (which UC call populates
     [uc+0x120]) — the pinned anchors: sMethods A 0x82f64b0 (56 rows
     stride 0x18), table B 0x82f69f0, choice = [uc+0x103] bit0,
     ioGpuUserClientTypeStatic 0x7f20260 via the gtype table 0x7f20270
     (slot fn 0x84f2124: metaclass 0x7f30218, classSize 0x138, singleton
     0xb8a6440). THEN p143 v2 = attach → re-census sel 0x24.
   - The state-band = DERIVED (record {+0 ptr, +8 u32, +0x10 valid} @0x18
     at PP+0x48; idx=[entry+0x424]; the 0xcda1 PAC law fleet-class).
3. **The AVE2 configure intake (the unvalidated store)**
   - configure 0x887660c stores param_5 → [ctx+0x110] UNVALIDATED
     (str @0x8876758; null-checks only) — the second write-cluster
     intake on the same kext; the property that controls param_5 =
     the next knob decode (the 112xxx-class intake law).

## The post-KRW pipeline (already built, gates on the receipt)
- Lum1naBootstrap: staging → the KRW self-test gate → inject →
  dpkg -i Sileo/Zebra → respring. HOLD until the gate passes.
- The self-test machinery = PROVEN (the mini's legal YES via cs2:
  kslide 0x22a2c000, kbase 0xfffffff029a30000, 2026-11-01).

## The tools proven tonight (all on the Mac)
- capstone 5.0.7 + the flat-delta law (fileoff = va_low48 - 0x7004000,
  24A435/23F77/24B119) = the static disasm of ANY band on ANY of the
  three caches without Ghidra.
- idevicecrashreport over USB (the 17) = the crash/panic pulls.
- The frida+ssh root lane (the mini): p140_run/p140_duo + the libkrw
  ABI (version/kbase/kread/.../kcall) + mach_port_kobject (type only;
  the kaddr hidden on both trains).
- The .ips three-slides law: the panic's Kernel-SLIDE (0x34360000-class)
  unslides the KERNEL/kext band; the text-exec slide = a DIFFERENT
  value; using the wrong one = the fake-neighbor decode.
- p093's intel table = the offset DB (LADDER/GHIDRA/PROVEN/LEAD rows)
  = the every-lane anchor source.

## The tap ladder for the 17 (each = one tap, honest rows)
1. p143 v2 (the owner-selector decode first) = the door's device proof.
2. p142 v7 (encode >=1 frame at N=8 so FUN_fffffe0008790cec stores a
   heap `this` at ctx+0x147b0, then Set 16463 re-init, then encode).
   v6 Set-then-encode is the this=1 / FAR=0x59 failed-alloc panic
   (IPS 13:45-13:55). Ghidra: ctor/dtor FUN_fffffe0008840f78 /
   FUN_fffffe0008840fec queue_init at this+0x58; dtor then
   kfree(this+0x50, count<<5) with count at this+0x48.
   **p149 v4 correction (2026-11-09):** the materialize premise was never
   verified — `EncodeFrame` can return 0 and still drop the frame with
   RealTime=false. v4 adds a hardware-encoder spec, an IOSurface-backed
   source, `VTCompressionSessionCompleteFrames` after the N=8 encode, and a
   delivered-sample-buffer counter. If `frames=0`, the overshoot is skipped
   and the session is leaked on purpose: running Set/invalidate there is the
   known this=1 FAR=0x59 panic. A bad `p142_layers.txt` now falls back to
   16462 (survival), never silently to 16463. The log line to read is
   `[2e] materialize drain st=… frames=…`; frames>0 is the first real
   evidence that ctx+0x147b0 holds a heap object.
3. **p149** is the conversion TAP: kernel pipe spray + p142 v7 sequence
   + scan for PIPE-HIT / QUEUE-INIT self-pointers + kread32 gate.
   KERNEL T1 on T8150 fires P114 then P149. Catalog p149 is the solo
   conversion fire after reboot. P110 stays catalog-solo.
4. The gate = kread32(kbase)==0xfeedfacf = the ONLY hasKread flip.
   PIPE-HIT / a panic PC / IPS slide never set slide.
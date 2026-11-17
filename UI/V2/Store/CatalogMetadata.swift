//
//  CatalogMetadata.swift
//  Lum1na — thin UI metadata over ExploitManager.catalog (no attack logic).
//

import Foundation

enum TestGroup: String, CaseIterable, Identifiable, Hashable {
    case probes = "Probes"
    case taps = "Taps"
    case chains = "Chains"
    case kernelReads = "Kernel reads"
    case parked = "Parked / CLOSED"
    var id: String { rawValue }
}

struct CatalogUIMeta: Identifiable, Hashable {
    let id: String
    let displayName: String
    let group: TestGroup
    let staticBadges: [HonestyBadgeKind]
    let subtitle: String
}

enum CatalogMetadata {
    /// Prefer first catalog row when ids collide; hide pure aliases.
    static let hiddenAliasIds: Set<String> = ["luminakrw", "p063"]

    private static let table: [String: CatalogUIMeta] = [
        "board": CatalogUIMeta(id: "board", displayName: "Kernel board JSON", group: .kernelReads, staticBadges: [], subtitle: "Documents/lum1na_board.json -- leaks, pins, hasKread."),
        "afterkread": CatalogUIMeta(id: "afterkread", displayName: "After-kread plan", group: .kernelReads, staticBadges: [.armGated], subtitle: "KRW test (MH_MAGIC_64), AMFI TC, opainject launchdhook, Sileo then Zebra, respring. HOLD u"),
        "dopaminecompat": CatalogUIMeta(id: "dopaminecompat", displayName: "Dopamine 3.0.10 compat", group: .parked, staticBadges: [.closed], subtitle: "CPU Vortex/Tempest=A12. OS 26.6 > End 26.0.1. hop-1 dead. Does not bump End."),
        "krwlib": CatalogUIMeta(id: "krwlib", displayName: "B1 libkrw harness", group: .kernelReads, staticBadges: [], subtitle: "Beta 1 rig path: libkrw provider → feedfacf self-test → commitSlide. Not the shipped chain"),
        "cs2core": CatalogUIMeta(id: "cs2core", displayName: "B1 ClearSword core", group: .kernelReads, staticBadges: [], subtitle: "Beta 1 path #2: verbatim Dopamine 3.0.11 ClearSword core → feedfacf self-test → commitSlid"),
        "ident": CatalogUIMeta(id: "ident", displayName: "Ident", group: .probes, staticBadges: [], subtitle: "hw.machine + kern.osversion + LabOff. Run first."),
        "krw": CatalogUIMeta(id: "krw", displayName: "T1 SKU DOOR", group: .chains, staticBadges: [], subtitle: "KERNEL sequencer path-test-3. Hunt: P044 N=192 + conversion Arm. 17: P139+P114 leak pair ("),
        "pathtest": CatalogUIMeta(id: "pathtest", displayName: "PATH SCORECARD", group: .chains, staticBadges: [], subtitle: "Per-path oracles. Hunt: P139+kread. 17 formula leak(P114)→race(P110)→write(P142) stays cat"),
        "krw2": CatalogUIMeta(id: "krw2", displayName: "T2 FACET A", group: .chains, staticBadges: [], subtitle: "64788 1x65535 + Trap2 sel=3 UAF oracle. Isolate from T1. Not kreadbuf."),
        "krw3": CatalogUIMeta(id: "krw3", displayName: "T3 ANE→SOCK", group: .chains, staticBadges: [], subtitle: "43748 fill then SocketKRW icmp6filt. Expected SKIP (inpcb ≠ 3072). Isolate."),
        "krw4": CatalogUIMeta(id: "krw4", displayName: "T4 LS SPY", group: .chains, staticBadges: [], subtitle: "Dual-wrap last-wire spy. 18:45 GPU OOM sealed. Isolate GPU from T1/T2."),
        "krw5": CatalogUIMeta(id: "krw5", displayName: "T5 PAC HOLD", group: .chains, staticBadges: [.armGated], subtitle: "Dopamine badRecovery / 65330 map. kcall after kread. Does not fire hop-1."),
        "krw6": CatalogUIMeta(id: "krw6", displayName: "T6 PPL inject", group: .chains, staticBadges: [.armGated], subtitle: "Titan A14 / momentarius map. Always runs AfterKread; AMFI/opainject HOLD without hasKread."),
        "krw7": CatalogUIMeta(id: "krw7", displayName: "T7 PHYS MAP", group: .chains, staticBadges: [], subtitle: "phys-map-3: DT reg + CacheMode dump + P069 mach_vm_map of that surface + MapMemory on DART"),
        "badquery": CatalogUIMeta(id: "badquery", displayName: "BadQuery Sandbox Escape", group: .taps, staticBadges: [], subtitle: "SANDBOX: file-path extension only. Not IOKit, not KRW."),
        "lightsword": CatalogUIMeta(id: "lightsword", displayName: "LightSword full chain", group: .chains, staticBadges: [], subtitle: "KRW head: victim A + spy B (heap-overlap / dual-wrap) → detach A → spray → blit B → inpcb "),
        "lsabc": CatalogUIMeta(id: "lsabc", displayName: "LightSword A/B/C blit", group: .chains, staticBadges: [], subtitle: "Fill/detach/replace + D spy (heap-overlap / dual-wrap). Kill-shot if D stale=1. Not KRW."),
        "coldforge": CatalogUIMeta(id: "coldforge", displayName: "ColdForge GMD reclaim", group: .chains, staticBadges: [], subtitle: "Ordered sel36 â replace â same-type hold â sel36. Confused-deputy candidate, not KRW"),
        "swordforge": CatalogUIMeta(id: "swordforge", displayName: "P122 SwordForge (combined 64788 KRW test)", group: .chains, staticBadges: [], subtitle: "P009 freer + mag reclaim + sel36 read + Shape-1 hunt. One 64788 chain per tap. Honest gate"),
        "shapecensus": CatalogUIMeta(id: "shapecensus", displayName: "P123 ShapeCensus (mini kalloc.3072 victim census)", group: .probes, staticBadges: [], subtitle: "KRW-vision census of kalloc.3072 on KRW lanes (mini/libkrw). Names the Shape-L victim for "),
        "descforge": CatalogUIMeta(id: "descforge", displayName: "P113 DescForge (mach-msg desc confusion control)", group: .taps, staticBadges: [], subtitle: "16 live port descs + tag, kernel marker scan, desc-type word OOL swap + body-tag control, "),
        "swordchain": CatalogUIMeta(id: "swordchain", displayName: "P125 SwordChain265 (one-click KRW test)", group: .chains, staticBadges: [], subtitle: "ONE-CLICK 26.5 KRW: same sequencer as KERNEL T1 (KRWChainController). Occupancy TAP then P"),
        "p165": CatalogUIMeta(id: "p165", displayName: "P165 sandbox unpatch (post-KRW; refuses honestly pre-KRW)", group: .taps, staticBadges: [.armGated], subtitle: "STEP 7.5 of KERNEL T1 as a tappable: proc_ro -> ucred -> cr_label -> sandbox ext-set -> '/"),
        "lsidcalib": CatalogUIMeta(id: "lsidcalib", displayName: "LSIDCalib (ID-sweep window dial, warm-hot set)", group: .taps, staticBadges: [], subtitle: "The rig's proven v10 ID-sweep calib, ported to main: classifies the window lottery THIS bo"),
        "rapier": CatalogUIMeta(id: "rapier", displayName: "Rapier sel36 race", group: .chains, staticBadges: [], subtitle: "64788 race fallback. A waits for B cycle 1. Isolate from p017v2. Not KRW."),
        "anvil": CatalogUIMeta(id: "anvil", displayName: "Anvil ANE reach", group: .chains, staticBadges: [], subtitle: "H11ANE IOServiceOpen gate. No 254 eval, no ProgramSendRequest."),
        "aks": CatalogUIMeta(id: "aks", displayName: "AKS KASLR Leak", group: .taps, staticBadges: [], subtitle: "CVE-2026-65343 23F77/23G71 KASLR. ACM capture + P010 size sweep. Not KRW."),
        "staleentry": CatalogUIMeta(id: "staleentry", displayName: "IOGPU Stale-Entry Oracle", group: .probes, staticBadges: [], subtitle: "64788-A: Metal 1x65535 → stale resource entry; 0xe00002be = UAF landed. Not kread."),
        "replacerace": CatalogUIMeta(id: "replacerace", displayName: "IOGPU Replace Race Lab", group: .taps, staticBadges: [], subtitle: "64788-B: detach+replace freer Ã GPU consumer race. Panic lab, durable log."),
        "stalepage": CatalogUIMeta(id: "stalepage", displayName: "GPU Stale-Page UAF", group: .taps, staticBadges: [], subtitle: "64788-C: dangling GART â freed pages; GPU R/W of reclaimed kernel heap. Self-verifying v"),
        "p027": CatalogUIMeta(id: "p027", displayName: "P027 Metal Callback", group: .probes, staticBadges: [], subtitle: "IOGPU sel=25 callback smoke (stride 0x40). Gadget, not KRW. Pair with LightSword GPU."),
        "socketkrw": CatalogUIMeta(id: "socketkrw", displayName: "Socket KRW Layer", group: .chains, staticBadges: [], subtitle: "Socket KRW layer. Arm only from LightSword with a real rw_inpcb. This tap is Probe-only."),
        "p044": CatalogUIMeta(id: "p044", displayName: "P044 ANE 254-Input", group: .taps, staticBadges: [], subtitle: "254 fill. Isolate. 23G71 fill_cap SKIP. icmp6filt via LabOff. KERNEL auto uses P044AksKasl"),
        "conv": CatalogUIMeta(id: "conv", displayName: "P044 conversion bar (N=192 / SKU model)", group: .taps, staticBadges: [], subtitle: "Live 43748 conversion TAP. Hunt 23F77 default N=192 1-record OOB. 12 mini 21D50 uses 127-i"),
        "p044chain": CatalogUIMeta(id: "p044chain", displayName: "P044 -> ANE254 chain", group: .chains, staticBadges: [], subtitle: "P044 then SocketKRW (real chain, in-app). Isolate. 23G71 fill_cap SKIP. AKS is not a fill "),
        "p056": CatalogUIMeta(id: "p056", displayName: "P056 VTCompression AVE", group: .taps, staticBadges: [], subtitle: "AVE VideoToolbox Create+Prepare+1 EncodeFrame. 254 mlmodelc cannot use this path."),
        "aio84530": CatalogUIMeta(id: "aio84530", displayName: "AIO Kqueue Leak Reader", group: .kernelReads, staticBadges: [], subtitle: "CVE-2026-84530 - proc_pidfdinfo reader on own process."),
        "p065": CatalogUIMeta(id: "p065", displayName: "P065 Facet A oracle", group: .probes, staticBadges: [], subtitle: "64788 1x65535 + Trap2 sel=3. 0xe00002be Call1 UAF oracle. Not kreadbuf."),
        "p066": CatalogUIMeta(id: "p066", displayName: "P066 EncType MAP", group: .taps, staticBadges: [], subtitle: "84607 EncType. One 128x128 H.264 VT session. Distinct from P061 dual-session. No Close-vs-"),
        "p067": CatalogUIMeta(id: "p067", displayName: "P067 AppleAVD reach", group: .taps, staticBadges: [], subtitle: "65407 AVD IOServiceOpen types 0..3. No bitstream remaining-fire."),
        "p068": CatalogUIMeta(id: "p068", displayName: "P068 chroot MAP", group: .taps, staticBadges: [], subtitle: "43689 chroot/seteuid errno MAP. No jail_priv fire."),
        "p069": CatalogUIMeta(id: "p069", displayName: "P069 dmaCommand MAP", group: .taps, staticBadges: [], subtitle: "43684 one IOSurface mach_vm_map. Local mach_vm_map prototype. No unbounded +0x34."),
        "p101": CatalogUIMeta(id: "p101", displayName: "P101 dmaCommand FIRE", group: .probes, staticBadges: [], subtitle: "43684 IOMD dmaref chain v2 (23F77 law): sel-2-class gate oracle, 65,537-retain u16 wrap (m"),
        "p103": CatalogUIMeta(id: "p103", displayName: "P103 M2Scaler census", group: .probes, staticBadges: [], subtitle: "M2ScalerCSCDriver opens-only user_* census (sel 8/11 semantics, K2U/K2K boundary denials)."),
        "p106": CatalogUIMeta(id: "p106", displayName: "P106 JPEG teardown oracle", group: .probes, staticBadges: [], subtitle: "AppleJPEGDriver sel5 +0x30==0 early-teardown two-call oracle (note 234); JpegRequest kallo"),
        "p107": CatalogUIMeta(id: "p107", displayName: "P107 AVE2 wrap-dims oracle", group: .probes, staticBadges: [], subtitle: "VTCompressionSession 16384x16384 (w*h*10 int32 wrap; MulDimsBitDepth 0x8240968 has no chec"),
        "p104": CatalogUIMeta(id: "p104", displayName: "P104 SEPKeyStore census", group: .probes, staticBadges: [], subtitle: "AppleSEPKeyStore opens-only sel census (163-sel table; sels 7/17/31 handle-0 gate verdicts"),
        "p161": CatalogUIMeta(id: "p161", displayName: "P161 SEPKeyStore test-UC sweep", group: .taps, staticBadges: [], subtitle: "v2: opens AppleKeyStore/AppleKeyStoreTest/AppleSEPKeyStore with types 0-32 (v1 stopped aft"),
        "p163": CatalogUIMeta(id: "p163", displayName: "P163 DPC translation oracle", group: .probes, staticBadges: [], subtitle: "Forge one port descriptor's type word to OOL and send/receive it (control, low-user and ke"),
        "p105": CatalogUIMeta(id: "p105", displayName: "P105 IOSurface gates", group: .probes, staticBadges: [], subtitle: "Framework-level gate census: global-create/lookup warn-once, protection-bits oracle, memor"),
        "p109": CatalogUIMeta(id: "p109", displayName: "P109 ANE sel sweep", group: .probes, staticBadges: [], subtitle: "ANE sel sweep with the Stage-B kernel oracle (kr 0x2f0 = door). H11ANEIn + LoadBalancer, t"),
        "p108": CatalogUIMeta(id: "p108", displayName: "P108 DiskImages census", group: .probes, staticBadges: [], subtitle: "AppleDiskImages2 / IOHDIXHDDriveInKernel / KDIDiskImageNubUserClient census: opens + sels "),
        "p112": CatalogUIMeta(id: "p112", displayName: "P112 cgshading oracle", group: .probes, staticBadges: [], subtitle: "CVE-2026-112611 CG Type-5 shading OOB oracle (in-process PDF + render; chosen-double value"),
        "p114": CatalogUIMeta(id: "p114", displayName: "P114 M2Scaler sel-8 leak tap", group: .taps, staticBadges: [], subtitle: "SOLO AppleM2ScalerCSCDriver sel-8 (iosaDiag) leak law validation (p110 v2 pairing gate): {"),
        "p102": CatalogUIMeta(id: "p102", displayName: "P102 Titan write TEST", group: .taps, staticBadges: [], subtitle: "Titan write TEST. MapMemory look-for IORVBAR + CacheMode canary. SKIPs MMIO store without "),
        "p070": CatalogUIMeta(id: "p070", displayName: "P070 five-door census", group: .chains, staticBadges: [], subtitle: "Five KRW doors + IOService census + AMFI persist HOLD. No 254 fire."),
        "p071": CatalogUIMeta(id: "p071", displayName: "P071 ANE overflow MAP", group: .probes, staticBadges: [], subtitle: "65408 DeviceOpen 0x68. Distinct from 43748 fill. No ProgramSendRequest."),
        "p072": CatalogUIMeta(id: "p072", displayName: "P072 file-parser census", group: .probes, staticBadges: [], subtitle: "dlopen census + 1x1 PNG. In-app ACE cannot skip kread. No trigger.pdf."),
        "p073": CatalogUIMeta(id: "p073", displayName: "P073 2nd-table + desc-smash scan", group: .taps, staticBadges: [], subtitle: "43748 second ANE MemoryMap table conversion (v15: bandit dial + D1/D2 detectors + desc-sma"),
        "p074": CatalogUIMeta(id: "p074", displayName: "P074 kernel dump via libkrw", group: .kernelReads, staticBadges: [.armGated], subtitle: "libkrw kread bulk dump to Documents. Honest failure on stock devices. Never claims hasKrea"),
        "p075": CatalogUIMeta(id: "p075", displayName: "P075 FomoPeek census", group: .probes, staticBadges: [], subtitle: "libapptracecore surface census (IOSurfaceRoot/IOAccelerator types/AddClient pairs). Intel-"),
        "ht149041": CatalogUIMeta(id: "ht149041", displayName: "HT149041 26.7 chain map", group: .chains, staticBadges: [], subtitle: "Print-only iOS 26.7 CVE map. Catalog p064 stays the AVE racer."),
        "darksword": CatalogUIMeta(id: "darksword", displayName: "P091 DarkSword chain map", group: .chains, staticBadges: [], subtitle: "Print-only GhostWave chain map + hostile strip list + LPE slot contract. Static."),
        "liter8": CatalogUIMeta(id: "liter8", displayName: "P092 Liter8 patch map", group: .probes, staticBadges: [.armGated], subtitle: "Print-only iOS 27 CFW kernel patch study + AfterKread checklist. Static."),
        "intel": CatalogUIMeta(id: "intel", displayName: "P093 intel cross-check", group: .kernelReads, staticBadges: [], subtitle: "Merged intel offset DB print + ladder-vs-LabOff usecount cross-check. Read-only."),
        "p094": CatalogUIMeta(id: "p094", displayName: "P094 kernproc derive", group: .kernelReads, staticBadges: [.armGated], subtitle: "READ-ONLY kernproc derivation (sysctl anchor / proven __DATA scan / LEAD validation). Zero"),
        "p095": CatalogUIMeta(id: "p095", displayName: "P095 ucred ladder", group: .kernelReads, staticBadges: [.armGated], subtitle: "READ-ONLY ucred ladder validation (cr_posix + label + audit_token) before elevate writes. "),
        "p097": CatalogUIMeta(id: "p097", displayName: "P097 console-sec leak", group: .kernelReads, staticBadges: [], subtitle: "CVE-2026-65371 gRegistryRoot instance leak via IOConsoleSecurityInterest (vschko). READ-ON"),
        "p098": CatalogUIMeta(id: "p098", displayName: "P098 m2scaler diag", group: .kernelReads, staticBadges: [], subtitle: "AppleM2ScalerCSCDriver iosaDiag event_payload IOSurface KVA leak (vschko, maybe CVE-2026-6"),
        "p099": CatalogUIMeta(id: "p099", displayName: "P099 ANE prewire groom", group: .taps, staticBadges: [.armGated], subtitle: "43748 groomed ANE prewire OOB (254-in direct path, rig port). ONE evaluation per tap, neve"),
        "kreadtest": CatalogUIMeta(id: "kreadtest", displayName: "KREAD commitSlide test", group: .kernelReads, staticBadges: [], subtitle: "kread32(kbase)==MH_MAGIC_64. Occupancy / 0xe00002be / heap never pass."),
        "p051": CatalogUIMeta(id: "p051", displayName: "P051 gamed census", group: .probes, staticBadges: [], subtitle: "gamed XPC selector census + in-cache benign write. No WVEK overflow, no TrollRestore. hasK"),
        "p054": CatalogUIMeta(id: "p054", displayName: "P054 APFS ReapList", group: .taps, staticBadges: [], subtitle: "reaplist occupancy probe - tap adapter."),
        "p010": CatalogUIMeta(id: "p010", displayName: "P010 Queue Leak", group: .kernelReads, staticBadges: [], subtitle: "QueueCreate copyout. LabOff size/leak (A14 0x410/+0x558, A12X 0x408/+0x550). Not KRW."),
        "p017v2": CatalogUIMeta(id: "p017v2", displayName: "P017 Confused Deputy", group: .probes, staticBadges: [], subtitle: "64788 magazine reclaim diagnostic. cd8 is not KRW."),
        "p032": CatalogUIMeta(id: "p032", displayName: "P032 ANE Open", group: .probes, staticBadges: [], subtitle: "H11ANEIn open/close reach only. No ProgramSendRequest."),
        "p033": CatalogUIMeta(id: "p033", displayName: "P033 CoreML 1-in/1-out", group: .probes, staticBadges: [], subtitle: "Legal CoreML ABI. Needs simple_1in1out.mlmodelc in bundle."),
        "p034": CatalogUIMeta(id: "p034", displayName: "P034 kmsg occupancy", group: .taps, staticBadges: [], subtitle: "kmsg 0x820 occupancy. No 254 fire."),
        "p040": CatalogUIMeta(id: "p040", displayName: "P040 Namespace dest", group: .taps, staticBadges: [], subtitle: "QueueCreate/Destroy dest ABI. No close-vs-method."),
        "p041": CatalogUIMeta(id: "p041", displayName: "P041 Slide dest map", group: .taps, staticBadges: [], subtitle: "43724 dest-class dump. No #536 blob."),
        "p042": CatalogUIMeta(id: "p042", displayName: "P042 IOGPU kptr scan", group: .taps, staticBadges: [], subtitle: "IOGPU type=1 selector kptr scan. No slide blob."),
        "p046": CatalogUIMeta(id: "p046", displayName: "P046 F77 patch oracle", group: .probes, staticBadges: [], subtitle: "Leftover MAP. 23G71 Ghidra: 64788 live, fill_cap, 64751 FIXED. No fire."),
        "p050": CatalogUIMeta(id: "p050", displayName: "P050 getattrlist", group: .taps, staticBadges: [], subtitle: "buflet getattrlist occupancy. Not a proven OOB."),
        "p053": CatalogUIMeta(id: "p053", displayName: "P053 NECP", group: .parked, staticBadges: [.closed], subtitle: "PHASE 1 NECP socket reach. 23G71 64751 FIXED — skip PHASE 2 race."),
        "p055": CatalogUIMeta(id: "p055", displayName: "P055 IOSurface UPL", group: .probes, staticBadges: [], subtitle: "IOSurface stale-mapping oracle. Mapping outlives CFRelease. Not KRW."),
        "p009": CatalogUIMeta(id: "p009", displayName: "P009 Replace Backing PathB", group: .probes, staticBadges: [], subtitle: "Proven F signature (stale GPU), not W. LabOff queue size."),
        "p038": CatalogUIMeta(id: "p038", displayName: "P038 W-hunt open", group: .probes, staticBadges: [], subtitle: "OPEN-only DiskImages2/IOHDIX/IOSurfaceAccelerator. No mount."),
        "p043": CatalogUIMeta(id: "p043", displayName: "P043 syscall 536 map", group: .taps, staticBadges: [], subtitle: "shared_region_map_and_slide_2_np reach. No #536 blob."),
        "p045": CatalogUIMeta(id: "p045", displayName: "P045 kmsg oracle", group: .probes, staticBadges: [], subtitle: "kmsg recv of own markers. Recv â  kread."),
        "p052": CatalogUIMeta(id: "p052", displayName: "P052 nstream extend", group: .parked, staticBadges: [.closed], subtitle: "MAXFSIZE EFBIG already on 26.5. That overflow angle died."),
        "cskrw": CatalogUIMeta(id: "cskrw", displayName: "CSKRW page-hit race", group: .parked, staticBadges: [.closed], subtitle: "hop-1 SKIP (patched 26.1 both SKUs). No prefetch overlap remaining-fire."),
        "cscalib": CatalogUIMeta(id: "cscalib", displayName: "LightSwordCalib (socket-race)", group: .parked, staticBadges: [.closed], subtitle: "hop-1 SKIP. cluster_*_contig EINVAL unless UPL_PHYS_CONTIG since 26.1."),
        "apfs84523": CatalogUIMeta(id: "apfs84523", displayName: "CVE-2026-84523 APFS", group: .probes, staticBadges: [], subtitle: "nstream (P052/EFBIG) + wvek pin. 26.5 leftover is wvek."),
        "p057": CatalogUIMeta(id: "p057", displayName: "P057 WVEK reach", group: .taps, staticBadges: [], subtitle: "apfs_aks_create_wvek LabOff pin. G71 FUN_fffffff009ab24c0. len>0x210 is BRK."),
        "p058": CatalogUIMeta(id: "p058", displayName: "P058 JPEG driver", group: .taps, staticBadges: [], subtitle: "AppleJPEGDriver open. 24A435 +0x30 class. No teardown fire."),
        "p061": CatalogUIMeta(id: "p061", displayName: "P061 AVE EncType", group: .taps, staticBadges: [], subtitle: "H264+HEVC VT sessions. 84607 EncType class. No Close/async race."),
        "p064": CatalogUIMeta(id: "p064", displayName: "P064 AVE 84607 Racer", group: .parked, staticBadges: [.closed], subtitle: "Close-vs-async PARK remaining-fire. HT149041 print map is catalog id ht149041."),
        "p005": CatalogUIMeta(id: "p005", displayName: "P005 JIT entitlement", group: .probes, staticBadges: [], subtitle: "MAP_JIT entitlement check only."),
        "lockdownd": CatalogUIMeta(id: "lockdownd", displayName: "Lockdownd USB class", group: .parked, staticBadges: [.closed, .armGated], subtitle: "HOLD log. USB pairing class, not a device KRW tap."),
        "p100autopilot": CatalogUIMeta(id: "p100autopilot", displayName: "P100 AutoLearn (the shared bandit ledger auto-learn row)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p110": CatalogUIMeta(id: "p110", displayName: "P110 IOSurface swap-claim probe (CVE-2026-112477 claim window; v2.8 T8150 leak law)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p115": CatalogUIMeta(id: "p115", displayName: "P115 M2Scaler framework-path PEEK (the tpeek law)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p116": CatalogUIMeta(id: "p116", displayName: "P116 SandboxExt TOCTOU (read/write, v2 knobs)", group: .taps, staticBadges: [.armGated], subtitle: "v2: deterministic sandbox_extension NOFOLLOW TOCTOU. Documents/p116_path.txt = single out-"),
        "p164": CatalogUIMeta(id: "p164", displayName: "P164 MCM container census + deputy pool (live read map)", group: .probes, staticBadges: [], subtitle: "Enumerates MCM container classes 2/7/10/12/13/15, then resolves + LISTs the documented sys"),
        "p117": CatalogUIMeta(id: "p117", displayName: "P117 EntEcho (entitlement echo census)", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p118": CatalogUIMeta(id: "p118", displayName: "P118 BootLearn (boot-state learn)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p119": CatalogUIMeta(id: "p119", displayName: "P119 StaleUPL (the stale-UPL door census)", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p120": CatalogUIMeta(id: "p120", displayName: "P120 NewResourceDoor (the create-fail-after-insert door)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p121": CatalogUIMeta(id: "p121", displayName: "P121 IOGPU CloseMerge (the close-merge teardown census)", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p125": CatalogUIMeta(id: "p125", displayName: "P125 KernIpcRace (the kern_ipc race census)", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p126": CatalogUIMeta(id: "p126", displayName: "P126 DecmpfsLeak (the decmpfs leak census)", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p127": CatalogUIMeta(id: "p127", displayName: "P127 FencePress (the fence pressure census)", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p128": CatalogUIMeta(id: "p128", displayName: "P128 FenceRace (the fence race window)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p129": CatalogUIMeta(id: "p129", displayName: "P129 FenceFill (the fence fill window)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p130": CatalogUIMeta(id: "p130", displayName: "P130 FenceSecondTable (the fence second-table census)", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p131": CatalogUIMeta(id: "p131", displayName: "P131 QuickLookDetour (the detour + the stage-3 flag law)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p132": CatalogUIMeta(id: "p132", displayName: "P132 ChainFrame (the chain frame census)", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p133": CatalogUIMeta(id: "p133", displayName: "P133 ReadFrame (the read frame census)", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p134": CatalogUIMeta(id: "p134", displayName: "P134 RouteA", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p135": CatalogUIMeta(id: "p135", displayName: "P135 RouteB", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p136": CatalogUIMeta(id: "p136", displayName: "P136 RouteC", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p137": CatalogUIMeta(id: "p137", displayName: "P137 RouteC Latch", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p138": CatalogUIMeta(id: "p138", displayName: "P138 RouteD", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p139": CatalogUIMeta(id: "p139", displayName: "P139 BootIntel (boot intel census)", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p140": CatalogUIMeta(id: "p140", displayName: "P140 Mini ground-truth verifier (mach_port_kobject + lane reads)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p141": CatalogUIMeta(id: "p141", displayName: "P141 USB+Stockholm reachability oracle", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p142": CatalogUIMeta(id: "p142", displayName: "P142 AVE2 temporal-knob (CVE-2026-112705 public vector, credited MMdAS/Calif)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p143": CatalogUIMeta(id: "p143", displayName: "P143 Rocket submit door (the 17's IOGPU row-0/0x19 law)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p144": CatalogUIMeta(id: "p144", displayName: "P144 AVE2 IO_Config mask-intake census", group: .probes, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p145": CatalogUIMeta(id: "p145", displayName: "P145 Composition (spray x stage9 fill x discriminator)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p146": CatalogUIMeta(id: "p146", displayName: "P146 Knob setter v2 (the afc-bypass; line-per-knob)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p147": CatalogUIMeta(id: "p147", displayName: "P147 Lifecycle (the stale-slot UAF teardown battery + row presets x60/x120/x200)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p148": CatalogUIMeta(id: "p148", displayName: "P148 AVE2 blob intake (the +0x55c verbatim calibration)", group: .taps, staticBadges: [], subtitle: "Synced from Lum1na-Debug (the P007 rig dev copy). Honesty: each probe carries its own PANI"),
        "p149": CatalogUIMeta(id: "p149", displayName: "P149 T8150 KRW conversion (encode N=8 then Set 16463, kernel pipes, kread32 gate)", group: .taps, staticBadges: [], subtitle: "17 conversion TAP. Encode >=1 frame at N=8 so AVE Surface Pool this is a heap kalloc, then"),
    ]

    static func meta(for entry: ExploitCatalogEntry) -> CatalogUIMeta {
        if let m = table[entry.id] { return m }
        return CatalogUIMeta(id: entry.id, displayName: entry.name, group: .probes, staticBadges: [], subtitle: entry.description)
    }

    static func visibleCatalog() -> [ExploitCatalogEntry] {
        var seen = Set<String>()
        var out: [ExploitCatalogEntry] = []
        for e in ExploitManager.catalog {
            if hiddenAliasIds.contains(e.id) { continue }
            if seen.contains(e.id) { continue }
            seen.insert(e.id)
            out.append(e)
        }
        return out
    }
}

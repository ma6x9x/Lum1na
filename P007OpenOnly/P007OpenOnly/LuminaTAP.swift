//
//  LuminaTAP.swift — single dispatcher for every Lum1na-Debug probe id.
//  Classic Console and the Cinder Lab catalog both call execute(_:).
//

import Foundation
import Darwin

enum LuminaTAP {
    static func logTap(_ id: String) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let lp = docs.appendingPathComponent("p011_tap_log.txt")
        let fd = open(lp.path, O_CREAT | O_WRONLY | O_APPEND, 0o644)
        if fd >= 0 {
            let s = "TAP \(id) \(LabLocalMilitaryNow() as String)\n"
            s.withCString { write(fd, $0, strlen($0)) }
            fcntl(fd, F_FULLFSYNC)
            close(fd)
        }
    }

    static func blocked(_ id: String) -> String? {
        switch id {
        case "iogpu_close":
            return "STOP iogpu_close — XR leftover (sel=7-as-create / sel=26-as-submit).\n"
                + "Named 43805 dest is P040: live sel=6 0x410 then sel=7.\n"
        case "t014a", "t014b", "t014c", "t014d", "t014e", "t014f":
            return "STOP T014 — XR leftover close-vs-method / wrong selectors.\n"
        case "p014close":
            return "STOP p014close — XR leftover (sel=7 structIn as CREATE).\n"
        case "p010obj":
            return "STOP p010obj — SURVIVED 2026-08-31. Not last-ref UAF. Not KRW.\n"
        case "t019":
            return "STOP t019 — Lookup-nil under lock is XR leak class.\n"
        case "p011v3", "p011v4", "p011v5", "p011v6", "p011v7", "p011v8", "p011v9", "p011v10", "p012ctx",
             "p010pduaf", "p010twoconn", "p010pdsweep", "p010krwv2", "p014ane", "p014b", "p015", "p017":
            return "STOP \(id) — leftover wire/UAF race, not in the 23F77 prove set.\n"
        case "hop1", "hop-1", "lshop1":
            return "STOP hop-1 KEEP CLOSED (UPL_PHYS_CONTIG bail on 26.1+/27.0). Do not remaining-fire LightSword hop-1.\n"
        case "sel163", "aks163", "p057sweep":
            return "STOP 163-selector AKS crash sweep KEEP CLOSED.\n"
        case "trollrestore", "wvek", "p051fire":
            return "STOP TrollRestore/WVEK remaining-fire KEEP CLOSED (ACE + BRK fail-closed).\n"
        default:
            return nil
        }
    }

    /// P099/P073 remaining-fire 254-in. Probe still fires. Not the hunt-12 KRW chain.
    static func hunt12MafBanner(_ id: String) -> String {
        return """
        *** \(id) is STANDALONE 254-in occupancy. MAF = first OOB record into a FREE kalloc.3072.
        Hunt 12 23F77 KRW chain is KERNEL: P139 disclose (P010 QueueCreate copyout + P063 aio kptr) then P044 N=192 LIVE 1-record OOB, then SocketKRW.Arm(rw_inpcb), then kread32(kbase)==MH_MAGIC_64.
        P099/P073 254 is not that chain. Probe still fires. One TAP per force-quit.

        """
    }

    /// Runs the probe on the calling queue. LabEngine already hops off main.
    /// Every id is a learn.<id> LabBandit domain (promotion lattice).
    static func execute(_ id: String) -> String {
        logTap(id)
        if let stop = blocked(id) { return LuminaLearn.observeParked(id: id, log: stop) }
        LuminaLearn.begin(id)
        LuminaLearn.prepare(id)
        var result: String
        switch id {
        case "ident":       result = DeviceIdentProbe.runIdentity()
        case "board":       result = P007Board.tap()
        case "jpeg_dest":   result = JPEGDestTimeoutProbe.runDestAndTimeoutOracle()
        case "jpeg_fw":     result = JPEGFrameworkDecodeProbe.runFrameworkDecodeSmoke()
        case "iogpu_close": result = "STOP iogpu_close — intercepted. Use P040."
        case "p009detach":  result = P009ReplaceBackingSmoke.runDetachOnly()
        case "p009iopl":    result = "STOP p009iopl — leftover, not in prove set."
        case "p011v3", "p011v4", "p011v5", "p011v6", "p011v7", "p011v8", "p011v9", "p011v10", "p012ctx":
            result = "STOP \(id) intercepted — leftover wire race. Use P009 PathB + p017v2."
        case "p001a13vt":    result = AVEVTSmoke.performA13AVEVTLadder()
        case "p013ave":     result = AVEVTSmoke.performA14AVEDimLadder()
        case "vt_smoke":    result = AVEVTSmoke.performSmoke()
        case "p001dim":     result = AVEVTSmoke.performP001DimProbe()
        case "p001proc":    result = AVEVTSmoke.performP001ProcessProbe()
        case "p001cap":     result = AVEVTSmoke.performP001CapBoundaryProbe()
        case "p001ladder":  result = AVEVTSmoke.performP001FullLadderProbe()
        case "p001conn":    result = AVEVTSmoke.performP001VTConnHunt()
        case "p001xref":    result = AVEVTSmoke.performP001CrossRefProbe()
        case "p001ports":   result = AVEVTSmoke.performP001NewPortSweep()
        case "p001t3":      result = AVEVTSmoke.performP001T3Sentinel()
        case "spawnattrs":  result = SpawnAttrsProbe.runSpawnAttrsProbe()
        case "p010krwv2", "p010pduaf", "p010twoconn", "p010pdsweep":
            result = "STOP \(id) intercepted — leftover P010 UAF. Use p010qleak (K− only)."
        case "p010qspray":  result = AVEOpenSmoke.runP010QueueSpray()
        case "p010remain":  result = AVEOpenSmoke.runP010Remain()
        case "necp":        result = AVEOpenSmoke.runNECPProbe()
        case "necprace":    result = AVEOpenSmoke.runNECPRace()
        case "p005":        result = AVEOpenSmoke.runP005Probe()
        case "iopl":        result = AVEOpenSmoke.runIOPLLeak()
        case "aio":         result = AVEOpenSmoke.runAIOUAF()
        case "ave47map":    result = AVEOpenSmoke.runAVE64747Map()
        case "ave47ctl":    result = AVEOpenSmoke.runAVE64747Control()
        case "ave47vt":     result = AVEVTSmoke.perform64747VTWrap()
        case "ave47vtw":    result = AVEVTSmoke.perform64747VTTrueWrap()
        case "p035":        result = P035AVEWrapProbe.tap()
        case "p036":        result = P036AVEPaintProbe.tap()
        case "p037":        result = P037AVEPaintProbe.tap()
        case "p009pathb":   result = P009ReplaceBackingSmoke.runPathB()
        case "p009ranges":  result = P009ReplaceBackingSmoke.runPathBRanges()
        case "p009types":   result = P009ReplaceBackingSmoke.runTypeInventory()
        case "t018":        result = CowTruncProbe.runCowTruncRace()
        case "t018shadow":  result = CowTruncProbe.runCowTruncShadowRace()
        case "t018ver":     result = CowTruncProbe.runCowTruncVersionRace()
        case "t019":
            result = "STOP t019 intercepted — XR leak class. Do not re-tap."
        case "t014a", "t014b", "t014c", "t014d", "t014e", "t014f":
            result = "STOP T014 intercepted — XR leftover. Use P040 dest ABI only."
        case "cscali":      result = LightSwordCalib.runCalib()
        case "swordforge": result = P122SwordForge.tap()
        case "shapecensus": result = P123ShapeCensus.tap()
        case "lswarm":
            do {
                let fm = FileManager.default
                let docs = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first ?? ""
                let p = (docs as NSString).appendingPathComponent("lswkrw_arm.txt")
                if fm.fileExists(atPath: p) {
                    try? fm.removeItem(atPath: p)
                    result = "LSWORD ARM CLEARED — cs2 back on the patched-train gate."
                } else {
                    try? "LightSword arm 2026-10-24: calib-licensed cs2 ladder.".write(toFile: p, atomically: true, encoding: .utf8)
                    let hc = (try? String(contentsOfFile: (docs as NSString).appendingPathComponent("lightsword_hot.txt"), encoding: .utf8))?
                        .components(separatedBy: .newlines).filter { $0.hasPrefix("0x") }.count ?? 0
                    let n = hc > 0 ? hc
                        : ((try? String(contentsOfFile: (docs as NSString).appendingPathComponent("racecalib_hot.txt"), encoding: .utf8))?
                            .components(separatedBy: .newlines).filter { $0.hasPrefix("0x") }.count ?? 0)
                    result = "ARMED (explicit override; \(n) calib hot windows). NOTE: cs2 also auto-licenses when this device has >=8 calib windows — no toggle needed. Next: FRESH BOOT -> tap cs2 ONCE. Re-tapping lswarm clears the arm."
                }
            }
        case "cskrw":       result = LuminaClearSword.runKRW()
        case "cs2":         result = CS2Runner.runUpstream()
        case "intel":       result = P093IntelCrossCheck.tap()
        case "p156":        result = P156ProcLocate.tap()
        case "p014ane", "p014b", "p015", "p017":
            result = "STOP \(id) intercepted — leftover. Use p017v2 for holder/install."
        case "p016":        result = JPEGDestTimeoutProbe.runP016SoutDestUnlock()
        case "p018":        result = JPEGDestTimeoutProbe.runP018SoutMachPort()
        case "p019":        result = P019IoplBoundsProbe.runP019IoplBounds()
        case "p020":        result = P020MagazineAwareReclaim.run()
        case "p020v2":      result = P020v2MagazineDrain.run()
        case "p021":        result = P021AGXStageMask.run()
        case "p022":        result = P022Cpu0DrainDelay.run()
        case "p023":
            P023VtExtremeProbe.run()
            result = ContentView.readFreshLog(
                named: "p023_vt_extreme_log.txt",
                missing: "p023 finished but Documents/p023_vt_extreme_log.txt missing or empty")
        case "p024":
            P024NecpStringRace.tap()
            result = ContentView.readFreshLog(
                named: "p024_necp_string_race_log.txt",
                missing: "p024 finished but Documents/p024_necp_string_race_log.txt missing or empty")
        case "p014close":
            result = "STOP p014close intercepted — XR leftover. Use P040 dest ABI only."
        case "p010leak", "p010qleak":
            result = P010QueueLeak.tap()
        case "p025":
            P025NecpStringSpray.tap()
            result = ContentView.readFreshLog(
                named: "p025_necp_string_spray_log.txt",
                missing: "p025 finished but Documents/p025_necp_string_spray_log.txt missing or empty")
        case "p017v2":
            result = P017ConfusedDeputy.tap()
        case "p026":
            result = P026MetalNqCite.tap()
        case "p039":
            result = P039AVEExploitTrigger.tap()
        case "p051":
            result = P051APFSXattr.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p051_apfs_xattr_log.txt",
                    missing: "p051 finished but log missing")
            }
        case "p052":
            result = P052APFSNstream.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p052_nstream_log.txt",
                    missing: "p052 finished but log missing")
            }
        case "p053", "P053":
            result = P053NECPDoubleFree.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named:  "p053_necp_dfree_log.txt",
                    missing: "p053 finished but log missing")
            }
        case "p027":
            result = P027MetalCallback.tap()
        case "p028":
            result = P028ReentryA.tap()
        case "p029":
            result = P029Hammer.tap()
        case "p030":
            result = P030TwoQueue.tap()
        case "p031":
            result = P031ReclaimHit.tap()
        case "p032":
            result = P032ANEOpenSmoke.tap()
        case "p038":
            result = P038WHuntSmoke.tap()
        case "p040":
            result = P040NamespaceDestSmoke.tap()
        case "p041":
            result = P041SlideDestMap.tap()
        case "p054":
            result = P054APFSReapList.tap()
        case "p055":
            result = P055IOSurfaceUPL.tap()
        case "p033":
            result = P033CoreML1in1out.tap()
        case "p034":
            result = P034Kmsg3072Occupancy.tap()
        case "b1p1":
            result = B1_B2_LabTest.sharedInstance().phase1_mapAndLatch()
        case "b1p2":
            result = B1_B2_LabTest.sharedInstance().phase2_unmapAndReclaim()
        case "b1p3":
            result = B1_B2_LabTest.sharedInstance().phase3_latchedKick()
        case "b1p4":
            result = B1_B2_LabTest.sharedInstance().phase4_verifyReclaim()
        case "p042":
            result = P042ReachabilityProbe.tap()
        case "p043":
            result = P043WriteClassMap.tap()
        case "p044":
            result = P044AksKaslrReach.tap()
        case "conv", "p073":
            result = hunt12MafBanner(id) + P073AneSecondTable.tap()
        case "p074":
            result = P074AneConsume.tap()
        case "p075":
            result = P075AneKrw.tap()
        case "p077":
            result = P077AneYcraft.tap()
        case "p078":
            result = P078AneYcraft3.tap()
        case "p079":
            result = P079AneYcraftPad.tap()
        case "p080":
            result = P080AneYcraft127.tap()
        case "p081":
            result = P081AneForeignProbe.tap()
        case "p082":
            result = P082AneKernelSid.tap()
        case "p083":
            result = P083AneStagingHunt.tap()
        case "p076":
            result = P076GlyphProbe.tap()
        case "p076c":
            result = P076GlyphProbe.tapControlOnly()
        case "pathtest":
            result = LabPathTest.tap()
        case "krw", "kernel":
            result = P007KernelChain.tap()
        case "kreadtest":
            result = P007Board.tapKreadTest()
        case "p057", "aks":
            result = P057AksDeserialize.tap()
        case "p062":
            result = P062NEONSelfTest.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p062_neon_selftest_log.txt",
                    missing: "p062 finished but log missing")
            }
        case "aio84530", "p063":
            result = P063AioKqueueLeak.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p84530_aio_kqueue_log.txt",
                    missing: "p063 finished but log missing")
            }
        case "ht149041", "p064":
            result = P064Ht149041ChainMap.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p064_ht149041_chain_log.txt",
                    missing: "p064 finished but log missing")
            }
        case "p065", "facet":
            result = P065FacetAOracle.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p065_facet_a_log.txt",
                    missing: "p065 finished but log missing")
            }
        case "p066":
            result = P066AveEncTypeMap.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p066_ave_enctype_log.txt",
                    missing: "p066 finished but log missing")
            }
        case "p067":
            result = P067AvdReach.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p067_avd_reach_log.txt",
                    missing: "p067 finished but log missing")
            }
        case "p068":
            result = P068ChrootPrivMap.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p068_chroot_priv_log.txt",
                    missing: "p068 finished but log missing")
            }
        case "p069":
            result = P069DmaCommandMap.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p069_dma_command_log.txt",
                    missing: "p069 finished but log missing")
            }
        case "p070", "chains":
            result = P070ChainSequencer.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p070_chain_sequencer_log.txt",
                    missing: "p070 finished but log missing")
            }
        case "p071":
            result = P071AneOverflowMap.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p071_ane_overflow_log.txt",
                    missing: "p071 finished but log missing")
            }
        case "p072":
            result = P072FileParserMap.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p072_file_parser_log.txt",
                    missing: "p072 finished but log missing")
            }
        case "p084":
            result = P084PmapTtePUA.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p084_pmap_tte_puaf_log.txt",
                    missing: "p084 finished but log missing")
            }
        case "p085", "racer":
            result = P085AVE84607Racer.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p085_ave84607_racer_log.txt",
                    missing: "p085 finished but log missing")
            }
        case "p086", "dmafp":
            result = P086IomdDmaFingerprint.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p086_iomd_dma_fingerprint_log.txt",
                    missing: "p086 finished but log missing")
            }
        case "p090", "census":
            result = P090MomentariusTest.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p090_momentarius_log.txt",
                    missing: "p090 finished but log missing")
            }
        case "p094":
            result = P094KernprocDerive.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p094_kernproc_log.txt",
                    missing: "p094 finished but log missing")
            }
        case "p095":
            result = P095UcredLadder.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p095_ucred_log.txt",
                    missing: "p095 finished but log missing")
            }
        case "p109", "anesweep":
            result = P109AneSelSweep.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p109_ane_selsweep_log.txt",
                    missing: "p109 finished but log missing")
            }
        case "p113":
            result = P113DescForgeControl.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p113_descforge_log.txt",
                    missing: "p113 finished but log missing")
            }
        case "p108", "dicensus":
            result = P108DiskImagesCensus.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p108_diskimages_census_log.txt",
                    missing: "p108 finished but log missing")
            }
        case "p103", "m2census":
            result = P103M2ScalerCensus.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p103_m2scaler_census_log.txt",
                    missing: "p103 finished but log missing")
            }
        case "p106", "jpegteardown":
            result = P106JPEGTeardownOracle.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p106_jpeg_teardown_oracle_log.txt",
                    missing: "p106 finished but log missing")
            }
        case "p107", "avewrap":
            result = P107AveWrapDims.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p107_ave_wrap_dims_log.txt",
                    missing: "p107 finished but log missing")
            }
        case "p104", "sepks":
            result = P104SepksCensus.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p104_sepks_census_log.txt",
                    missing: "p104 finished but log missing")
            }
        case "p105", "iosgates":
            result = P105IosurfaceGates.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p105_iosurface_gates_log.txt",
                    missing: "p105 finished but log missing")
            }
        case "p101":
            result = P101DmaCommandFire.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p101_dma_command_fire_log.txt",
                    missing: "p101 finished but log missing")
            }
        case "p102":
            result = P102TitanWriteTest.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p102_titan_write_log.txt",
                    missing: "p102 finished but log missing")
            }
        case "p100", "learn":
            result = P100AutoLearn.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p100_learn_log.txt",
                    missing: "p100 finished but log missing")
            }
        case "p110", "swapclaim":
            result = P110SurfaceSwapClaim.tap()
        case "p110xleak":
            P110SurfaceSwapClaim.forceLeakgateArm()
            result = P110SurfaceSwapClaim.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p110_swapclaim_log.txt",
                    missing: "p110 finished but log missing")
            }
        case "p112", "cgshading":
            result = P112CGShading.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p112_cgshading_log.txt",
                    missing: "p112 finished but log missing")
            }
        case "p117", "entecho":
            result = P117EntEcho.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p117_entecho_log.txt",
                    missing: "p117 finished but log missing")
            }
        case "p116", "tocnou":
            result = P116SandboxExtTocTou.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p116_sandboxext_toctou_log.txt",
                    missing: "p116 finished but log missing")
            }
        case "p115", "m2peek":
            result = P115M2ScalerPeek.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p115_m2peek_log.txt",
                    missing: "p115 finished but log missing")
            }
        case "p114", "surfaceleak":
            result = P114SurfaceLeak.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p114_surfaceleak_log.txt",
                    missing: "p114 finished but log missing")
            }
        case "p118", "bootlearn":
            result = P118BootLearn.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p118_bootlearn_log.txt",
                    missing: "p118 finished but log missing")
            }
        case "p119", "staleupl":
            result = P119StaleUpl.tap()
        case "p120", "newresource":
            result = P120NewResourceDoor.tap()
        case "p121", "closemerge":
            result = P121IogpuCloseMerge.tap()
        case "p125", "kernipc":
            result = P125KernIpcRace.tap()
        case "p126", "decmpfs":
            result = P126DecmpfsLeak.tap()
        case "p127", "fencepress":
            result = P127FencePress.tap()
        case "p128", "fencerace":
            result = P128FenceRace.tap()
        case "p129", "fencefill":
            result = P129FenceFill.tap()
        case "p130", "fusesecond":
            result = P130FenceSecondTable.tap()
        case "p131", "qldetour":
            result = P131QuickLookDetour.tap()
        case "p132", "chainframe":
            result = P132ChainFrame.tap()
        case "p133", "readframe":
            result = P133ReadFrame.tap()
        case "p134", "routea":
            result = P134RouteA.tap()
        case "p135", "routeb":
            result = P135RouteB.tap()
        case "p136", "routec":
            result = P136RouteC.tap()
        case "p137", "latch":
            result = P137RouteCLatch.tap()
        case "p138", "routed":
            result = P138RouteD.tap()
        case "p139", "bootintel":
            result = P139BootIntel.tap()
        case "p140", "groundtruth":
            result = P140GroundTruth.tap()
        case "p141", "usbstockholm":
            result = P141UsbStockholm.tap()
        case "p142", "avetemporal":
            result = P142AVETemporal.tap()
        case "p143", "rocketdoor":
            result = P143RocketDoor.tap()
        case "p144", "ave2config":
            result = P144AVE2Config.tap()
        case "p145", "composition":
            result = P145Composition.tap()
        case "p146", "knobsetter":
            result = P146KnobSetter.tap()
        case "p147", "lifecycle":
            result = P147Lifecycle.tap()
        case "p147x60":
            P147Lifecycle.setPresetCycles(60)
            result = P147Lifecycle.tap()
        case "p147x120":
            P147Lifecycle.setPresetCycles(120)
            result = P147Lifecycle.tap()
        case "p147x200":
            P147Lifecycle.setPresetCycles(200)
            result = P147Lifecycle.tap()
        case "p148", "aveblob":
            result = P148AVE2Prepare.tap()
        case "p149", "t8150krw":
            result = P149T8150Krw.tap()
        case "p150", "aneucreach":
            result = P150ANEUCPReach.tap()
        case "p151", "anedeviceopen":
            result = P151ANEDeviceOpen.tap()
        case "p152", "iosurfgate":
            result = P152IOSurfaceLookupGate.tap()
        case "p153", "anesel":
            result = P153ANESelectorProbe.tap()
        case "p099", "anegroom":
            result = hunt12MafBanner(id) + P099AnePrewireGroom.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p099_aneprewire_log.txt",
                    missing: "p099 finished but log missing")
            }
        case "p098", "m2scaler":
            result = P098M2ScalerDiag.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p098_m2scaler_diag_log.txt",
                    missing: "p098 finished but log missing")
            }
        case "p097", "consolesec":
            result = P097ConsoleSecLeak.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p097_consolesec_log.txt",
                    missing: "p097 finished but log missing")
            }
        case "p088", "writehop":
            result = P088AneWriteHop.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p088_write_hop_log.txt",
                    missing: "p088 finished but log missing")
            }
        case "p087", "reclaim":
            result = P087ReclaimObserver.tap()
            if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                result = ContentView.readFreshLog(
                    named: "p087_reclaim_observer_log.txt",
                    missing: "p087 finished but log missing")
            }
        case "p045":
            result = P045HybridMap.tap()
        case "p046":
            result = P046F77PatchOracle.tap()
        case "p050":
            P050GetattrlistOOB.tap()
            result = ContentView.readFreshLog(
                named: "p050_getattrlist_oob_log.txt",
                missing: "p050 finished but Documents/p050_getattrlist_oob_log.txt missing or empty")
        case "luminakrw":
            result = LuminaKRW.tap()
        case "p022GC":
            P022GC_GameCenter_Sandbox_Escape.tap()
            result = ContentView.readFreshLog(
                named: "p022_gc_escape_log.txt",
                missing: "p022GC finished but Documents/p022_gc_escape_log.txt missing or empty")
        default:
            result = "unknown"
        }
        return LuminaLearn.finish(id, log: result)
    }
}

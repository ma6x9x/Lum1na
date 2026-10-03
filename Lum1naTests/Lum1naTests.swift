//
//  Lum1naTests.swift
//  Lum1naTests
//
//  Offset-table contract: A14 23F77 vs A12X 23G71 never share VAs.
//  Use LabOffForSku so simulator/host hw.machine cannot pick the wrong table.
//

import Testing
@testable import Lum1na

private func tag(_ off: UnsafePointer<LabOffTab>?) -> String {
    guard let off, let c = off.pointee.tag else { return "" }
    return String(cString: c)
}

struct Lum1naOffsetTests {

    @Test func a14TableIsT8101_23F77() {
        let off = LabOffForSku(.A14_23F77)
        #expect(off != nil)
        #expect(tag(off) == "A14_23F77")
        guard let t = off?.pointee else { return }

        #expect(t.queue_create_size == 0x410)
        #expect(t.queue_leak == 0x558)
        #expect(t.queue_create_sel == 6)
        #expect(t.submit_sel == 25)
        #expect(t.owns_replaceable == 0)
        #expect(t.ane_fill_cap == 0)
        #expect(t.sysmem_md == 0x90)
        #expect(t.iosurface_md == 0x30)
        #expect(t.gmd_elemsz == 0xb0)
        #expect(t.mag_cap == 8)
        #expect(t.sel36 == 36)
        #expect(t.panic_cc8 == 0xFFFFFFF009857CC8)
        #expect(t.panic_cd8 == 0xFFFFFFF009857CD8)
        #expect(t.panic_d00 == 0xFFFFFFF009857D00)
        #expect(t.socket_usecount == 0x23c)

        #expect(t.replace_bytes == 0xFFFFFFF0095E20D4)
        #expect(t.getter == 0xFFFFFFF0095E1BDC)
        #expect(t.fn4 == 0xFFFFFFF0095C94AC)
        #expect(t.ane_checkandprewire == 0xFFFFFFF00874C070)
        #expect(t.amfi_external == 0xFFFFFFF008B673F8)
        #expect(t.amfi_loadtc == 0xFFFFFFF008B67498)
        #expect(t.amfi_sel_copy == 2)
        #expect(t.amfi_sel_manifest == 7)
        #expect(t.pmap_cs_allow == 0xFFFFFFF00A610458)
        #expect(t.pmap_load_tc == 0xFFFFFFF00A60D8D0)
        #expect(t.ave_close == 0xFFFFFFF008371094)
        #expect(t.aks_wvek_overflow == 0xFFFFFFF009BD96D4)
        #expect(t.static_base == 0xFFFFFFF007004000)
        #expect(t.pmap_cs_allow_off == 0xca)
    }

    @Test func a12xTableIsT8020_23G71() {
        let off = LabOffForSku(.A12X_23G71)
        #expect(off != nil)
        #expect(tag(off) == "A12X_23G71")
        guard let t = off?.pointee else { return }

        #expect(t.queue_create_size == 0x408)
        #expect(t.queue_leak == 0x550)
        #expect(t.owns_replaceable == 1)
        #expect(t.ane_fill_cap == 1)
        #expect(t.sysmem_md == 0x90)
        #expect(t.iosurface_md == 0x30)
        #expect(t.gmd_elemsz == 0xb0)
        #expect(t.mag_cap == 8)

        #expect(t.replace_bytes == 0xFFFFFFF0094B8FE4)
        #expect(t.getter == 0xFFFFFFF0094E1070)
        #expect(t.fn4 == 0xFFFFFFF0094C8434)
        #expect(t.ane_checkandprewire == 0xFFFFFFF008701990)
        #expect(t.amfi_external == 0xFFFFFFF008B3FFE8)
        #expect(t.amfi_loadtc == 0xFFFFFFF008B40088)
        #expect(t.pmap_cs_allow == 0xFFFFFFF00A4DA8FC)
        #expect(t.pmap_load_tc == 0)
        #expect(t.ave_close == 0xFFFFFFF0083A4CF0)
        #expect(t.aks_wvek_overflow == 0xFFFFFFF009AB24C0)
        #expect(t.static_base == 0xFFFFFFF007004000)
        #expect(t.pmap_cs_allow_off == 0xca)
    }

    @Test func tablesDoNotPasteAcrossSilicon() {
        let a14 = LabOffForSku(.A14_23F77)!.pointee
        let a12 = LabOffForSku(.A12X_23G71)!.pointee

        #expect(a14.replace_bytes != a12.replace_bytes)
        #expect(a14.getter != a12.getter)
        #expect(a14.fn4 != a12.fn4)
        #expect(a14.ane_checkandprewire != a12.ane_checkandprewire)
        #expect(a14.amfi_loadtc != a12.amfi_loadtc)
        #expect(a14.pmap_cs_allow != a12.pmap_cs_allow)
        #expect(a14.ave_close != a12.ave_close)
        #expect(a14.aks_wvek_overflow != a12.aks_wvek_overflow)
        #expect(a14.queue_create_size != a12.queue_create_size)
        #expect(a14.queue_leak != a12.queue_leak)
        #expect(a14.owns_replaceable != a12.owns_replaceable)
        #expect(a14.ane_fill_cap != a12.ane_fill_cap)
    }

    @Test func liveLabOffFollowsDetectedSku() {
        let sku = LabDeviceProfile.detectedSku()
        let live = LabOff()
        switch sku {
        case .A14_23F77, .A14_other:
            #expect(tag(live).hasPrefix("A14"))
            #expect(live?.pointee.queue_create_size == 0x410)
            #expect(live?.pointee.owns_replaceable == 0)
        case .A12X_23G71, .A12X_other:
            #expect(tag(live).hasPrefix("A12X"))
            #expect(live?.pointee.queue_create_size == 0x408)
            #expect(live?.pointee.owns_replaceable == 1)
        default:
            #expect(live == nil)
        }
    }

    @Test func siblingBuildAliasesShareTable() {
        #expect(LabOffForSku(.A14_other) == LabOffForSku(.A14_23F77))
        #expect(LabOffForSku(.A12X_other) == LabOffForSku(.A12X_23G71))
        #expect(LabOffForSku(.unknown) == nil)
        #expect(LabOffForSku(.XR_22H311) == nil)
    }

    @Test @MainActor func catalogWiresColdForgeRapierAnvilAndABC() {
        let ids = Set(ExploitManager.catalog.map(\.id))
        #expect(ids.contains("coldforge"))
        #expect(ids.contains("rapier"))
        #expect(ids.contains("anvil"))
        #expect(ids.contains("lsabc"))
        #expect(ids.contains("p055"))
        #expect(ids.contains("lightsword"))
        #expect(ids.contains("krw"))
        #expect(ids.contains("krw2"))
        #expect(ids.contains("krw3"))
        #expect(ids.contains("krw4"))

        func cls(_ id: String) -> String {
            ExploitManager.catalog.first { $0.id == id }?.controllerClass ?? ""
        }
        #expect(cls("coldforge") == "ColdForge")
        #expect(cls("rapier") == "Rapier")
        #expect(cls("anvil") == "Anvil")
        #expect(cls("lsabc") == "LightSwordABC")
        #expect(cls("p055") == "P055IOSurfaceUPL")
        #expect(cls("anvil").isEmpty == false)
        #expect(cls("p044") == "P044ExploitController")
        #expect(cls("p044chain") == "ANE254ChainController")
        #expect(cls("krw") == "KRWChainController")
        #expect(cls("krw2") == "KRWTheoryFacetA")
        #expect(cls("krw3") == "KRWTheoryANESocket")
        #expect(cls("krw4") == "KRWTheoryLightSword")
        #expect(cls("afterkread") == "Lum1naAfterKread")
        #expect(ids.contains("dopaminecompat"))
        #expect(cls("dopaminecompat") == "DopamineCompat")
        #expect(cls("aks") == "AKSExploitController")
        #expect(cls("cscalib") == "CSRaceCalib")
        #expect(cls("cskrw") == "CSKRW")
    }

    @Test func probeLogsMapNewTaps() {
        #expect(PersistentLogStore.probeLogFiles["coldforge"] == "p06x_coldforge_log.txt")
        #expect(PersistentLogStore.probeLogFiles["rapier"] == "p06x_rapier_log.txt")
        #expect(PersistentLogStore.probeLogFiles["anvil"] == "p06x_anvil_log.txt")
        #expect(PersistentLogStore.probeLogFiles["lsabc"] == "p06x_lsabc_log.txt")
        #expect(PersistentLogStore.probeLogFiles["p055"] == "p055_iosurface_upl_log.txt")
        #expect(PersistentLogStore.probeLogFiles["p044"] == "p06x_p044_log.txt")
        #expect(PersistentLogStore.probeLogFiles["p044chain"] == "p06x_ane254chain_log.txt")
        #expect(PersistentLogStore.probeLogFiles["krw"] == "p06x_krw_log.txt")
        #expect(PersistentLogStore.probeLogFiles["krw2"] == "p06x_krw2_log.txt")
        #expect(PersistentLogStore.probeLogFiles["krw3"] == "p06x_krw3_log.txt")
        #expect(PersistentLogStore.probeLogFiles["krw4"] == "p06x_krw4_log.txt")
        #expect(PersistentLogStore.probeLogFiles["afterkread"] == "p06x_afterkread_log.txt")
        #expect(PersistentLogStore.probeLogFiles["dopaminecompat"] == "dopaminecompat_log.txt")
        #expect(PersistentLogStore.probeLogFiles["p053"] == "p053_necp_dfree_log.txt")
        #expect(PersistentLogStore.probeLogFiles["cscalib"] == "racecalib_log.txt")
    }

    @Test func boardRecordEventDedupeByEventAndKind() {
        let board = Lum1naBoard.shared()
        board.recordEvent("unit_test_coldforge", kind: "deputy",
                          detail: "first", source: "tests")
        board.recordEvent("unit_test_coldforge", kind: "deputy",
                          detail: "second", source: "tests")
        let rows = board.leaks.compactMap { $0 as? [String: Any] }.filter {
            ($0["va"] as? String) == "unit_test_coldforge"
                && ($0["kind"] as? String) == "deputy"
        }
        #expect(rows.count == 1)
        let hits = (rows.first?["hits"] as? NSNumber)?.intValue ?? 0
        #expect(hits >= 2)
        #expect((rows.first?["detail"] as? String) == "second")
    }
}

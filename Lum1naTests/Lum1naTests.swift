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
}

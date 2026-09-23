//
//  LabOffsets.swift
//  Lum1na
//
//  Runtime offset table with device detection
//  Supports A14 23F77 and A12X 23G71
//

import Foundation
import Darwin

// MARK: - Offset Table Structure
struct LabOffTab {
    let tag: String
    let static_base: UInt64
    
    // IOGPU offsets
    let sysmem_md: UInt32
    let iosurface_md: UInt32
    let gmd_elemsz: UInt32
    let queue_create_sel: UInt32
    let queue_create_size: UInt32
    let queue_destroy_sel: UInt32
    let submit_sel: UInt32
    let new_resource_sel: UInt32
    let sel7_min_in: UInt32
    let queue_leak: UInt32
    
    // Socket offsets
    let socket_usecount: UInt32
    let so_necp: UInt32
    let sol_socket: UInt32
    let necp_tlv: UInt32
    let necp_str_len: UInt32
    
    // ANE offsets (NEW)
    let ane_checkandprewire: UInt64
    let ane_memorymap: UInt64
    let ane_table_size: UInt32
    let ane_neighbor_bytes: UInt32
    
    // Panic offsets
    let panic_cc8: UInt64
    let panic_cd8: UInt64
    let panic_d00: UInt64
    
    // Function pointers
    let fn4: UInt64
    let getter: UInt64
    let replace_bytes: UInt64
    let assign_shared: UInt64
    
    // Cluster
    let cluster_w: UInt64
    let cluster_r: UInt64
    
    // AVE
    let ave_close: UInt64
    let ave_stop: UInt64
    let ave_async: UInt64
    
    // Magazine capacity
    let mag_cap: UInt32
}

// MARK: - Device Detection
func LabOff() -> LabOffTab {
    var name = utsname()
    uname(&name)
    let machine = withUnsafeBytes(of: &name.machine) { rawBufferPointer in
        let cString = rawBufferPointer.baseAddress!.assumingMemoryBound(to: CChar.self)
        return String(cString: cString)
    }
    
    // Detect device and return appropriate offsets
    if machine.contains("iPhone13") {
        // A14 devices: iPhone 12, 12 mini, 12 Pro, 12 Pro Max
        return gA14
    } else if machine.contains("iPad8") {
        // A12X devices: iPad Pro 11", iPad Pro 12.9" (3rd gen)
        return gA12X
    }
    
    // Default to A14
    return gA14
}

// MARK: - A14 23F77 Offsets
let gA14 = LabOffTab(
    tag: "A14_23F77",
    static_base: 0xFFFFFFF007004000,
    
    // IOGPU
    sysmem_md: 0x90,
    iosurface_md: 0x30,
    gmd_elemsz: 0xB0,
    queue_create_sel: 6,
    queue_create_size: 0x410,
    queue_destroy_sel: 7,
    submit_sel: 25,
    new_resource_sel: 0x08,
    sel7_min_in: 0x408,
    queue_leak: 0x558,
    
    // Socket
    socket_usecount: 0x23C,
    so_necp: 0x1109,
    sol_socket: 0xFFFF,
    necp_tlv: 0x07,
    necp_str_len: 255,
    
    // ANE (NEW - from A14_23F77_LabOffsets.h)
    ane_checkandprewire: 0xFFFFFFF00874C070,
    ane_memorymap: 0xFFFFFFF00874C7F4,
    ane_table_size: 0x820,
    ane_neighbor_bytes: 0x3E0,  // 254-input overflow into next chunk
    
    // Panic
    panic_cc8: 0xFFFFFFF009857CC8,
    panic_cd8: 0xFFFFFFF009857CD8,
    panic_d00: 0xFFFFFFF009857D00,
    
    // Functions
    fn4: 0xFFFFFFF0095C94AC,
    getter: 0xFFFFFFF0095E1BDC,
    replace_bytes: 0xFFFFFFF0095E20D4,
    assign_shared: 0xFFFFFFF009857C88,
    
    // Cluster
    cluster_w: 0xFFFFFFF009F97944,
    cluster_r: 0xFFFFFFF009F9DDA4,
    
    // AVE
    ave_close: 0xFFFFFFF008371094,
    ave_stop: 0xFFFFFFF008370174,
    ave_async: 0xFFFFFFF00837137C,
    
    // Magazine
    mag_cap: 8
)

// MARK: - A12X 23G71 Offsets
let gA12X = LabOffTab(
    tag: "A12X_23G71",
    static_base: 0xFFFFFFF007004000,
    
    // IOGPU (different from A14)
    sysmem_md: 0x90,
    iosurface_md: 0x30,
    gmd_elemsz: 0xB0,
    queue_create_sel: 6,
    queue_create_size: 0x408,  // Different from A14
    queue_destroy_sel: 7,
    submit_sel: 25,
    new_resource_sel: 0x08,
    sel7_min_in: 0x408,
    queue_leak: 0x550,  // Different from A14
    
    // Socket (same as A14)
    socket_usecount: 0x23C,
    so_necp: 0x1109,
    sol_socket: 0xFFFF,
    necp_tlv: 0x07,
    necp_str_len: 255,
    
    // ANE (A12X VAs are different)
    ane_checkandprewire: 0xFFFFFFF00877A000,  // Different VA
    ane_memorymap: 0xFFFFFFF00877A7F4,        // Different VA
    ane_table_size: 0x820,                     // Same size
    ane_neighbor_bytes: 0x3E0,                 // Same overflow
    
    // Panic (different from A14)
    panic_cc8: 0,
    panic_cd8: 0xFFFFFFF009E38A6C,
    panic_d00: 0,
    
    // Functions (different from A14)
    fn4: 0xFFFFFFF0094C8434,
    getter: 0xFFFFFFF0094E1070,
    replace_bytes: 0xFFFFFFF0094B8FE4,
    assign_shared: 0,
    
    // Cluster (different from A14)
    cluster_w: 0xFFFFFFF009E6B2B0,
    cluster_r: 0xFFFFFFF009E711F0,
    
    // AVE (different from A14)
    ave_close: 0xFFFFFFF0083A4CF0,
    ave_stop: 0xFFFFFFF0083A3DD0,
    ave_async: 0xFFFFFFF0083A4FD8,
    
    // Magazine (same as A14)
    mag_cap: 8
)

// MARK: - Helper Functions
func getCurrentDeviceTag() -> String {
    return LabOff().tag
}

func isA14() -> Bool {
    return LabOff().tag.hasPrefix("A14")
}

func isA12X() -> Bool {
    return LabOff().tag.hasPrefix("A12X")
}

//
//  LabOffsetsBridge.swift
//  Lum1na
//

import Foundation

/// Swift bridge to C LabOffTab structure
struct LabOffsetsBridge {
    
    // MARK: - Properties
    
    let tag: String
    let staticBase: UInt64
    let socketUsecount: UInt32
    let soNecpAttributes: UInt32
    let necpTlvType: UInt32
    
    // MARK: - Initialization
    
    init(cStruct: LabOffTab) {
        self.tag = String(cString: cStruct.tag)
        self.staticBase = cStruct.static_base
        self.socketUsecount = cStruct.socket_usecount
        self.soNecpAttributes = cStruct.so_necp
        self.necpTlvType = cStruct.necp_tlv
    }
}

// MARK: - Factory Function

func getDeviceOffsets() -> LabOffsetsBridge {
    let cTab = LabOff()
    return LabOffsetsBridge(cStruct: cTab.pointee)
}

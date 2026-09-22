// DeviceUtils.swift
// Lum1na Beta 1 - Device Support Utilities

import Foundation

enum LuminaChip: String {
    case a14 = "A14 Bionic"
    case a15 = "A15 Bionic"
    case a16 = "A16 Bionic"
    case a17 = "A17 Pro"
    case unknown = "Unknown"
}

struct DeviceUtils {
    static let a14Identifiers = [
        "iPhone13,1", "iPhone13,2", "iPhone13,3", "iPhone13,4",
        "iPad13,1", "iPad13,2"
    ]
    
    static let a15Identifiers = [
        "iPhone14,4", "iPhone14,5", "iPhone14,2", "iPhone14,3"
    ]
    
    static let a16Identifiers = [
        "iPhone14,7", "iPhone14,8", "iPhone15,2", "iPhone15,3"
    ]
    
    static let a17Identifiers = [
        "iPhone16,1", "iPhone16,2"
    ]
    
    static var supportedIdentifiers: [String] {
        return a14Identifiers + a15Identifiers + a16Identifiers + a17Identifiers
    }
    
    static var currentDeviceIdentifier: String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machineMirror = Mirror(reflecting: systemInfo.machine)
        let identifier = machineMirror.children.reduce("") { identifier, element in
            guard let value = element.value as? Int8, value != 0 else { return identifier }
            return identifier + String(UnicodeScalar(UInt8(value)))
        }
        return identifier
    }
    
    static var isSupportedDevice: Bool {
        return supportedIdentifiers.contains(currentDeviceIdentifier)
    }
    
    static var currentChip: LuminaChip {
        if a14Identifiers.contains(currentDeviceIdentifier) { return .a14 }
        if a15Identifiers.contains(currentDeviceIdentifier) { return .a15 }
        if a16Identifiers.contains(currentDeviceIdentifier) { return .a16 }
        if a17Identifiers.contains(currentDeviceIdentifier) { return .a17 }
        return .unknown
    }
    
    static var deviceCategory: String {
        switch currentChip {
        case .a14: return "iPhone 12 Series (A14)"
        case .a15: return "iPhone 13 Series (A15)"
        case .a16: return "iPhone 14 Series (A16)"
        case .a17: return "iPhone 15 Pro (A17)"
        case .unknown: return "Unsupported Device"
        }
    }
    
    static var expectedKBase: UInt64 {
        switch currentChip {
        case .a14, .a15: return 0xFFFFFFF007004000
        case .a16, .a17: return 0xFFFFFFF007008000
        case .unknown: return 0xFFFFFFF007004000
        }
    }
    
    static var kernelVersion: String {
        var uts = utsname()
        uname(&uts)
        return String(cString: &uts.release.0)
    }
}

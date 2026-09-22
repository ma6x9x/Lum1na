// DeviceUtils.swift
// Lum1na device identification. Keep this mapping aligned with LabDeviceProfile.

import Foundation

#if canImport(Darwin)
import Darwin
#endif

enum LuminaChip: String {
    case a12x = "A12X Bionic"
    case a14 = "A14 Bionic"
    case a15 = "A15 Bionic"
    case a16 = "A16 Bionic"
    case a17 = "A17 Pro"
    case unknown = "Unknown"
}

struct DeviceUtils {
    static let a12XIdentifiers = [
        "iPad8,1", "iPad8,2", "iPad8,3", "iPad8,4",
        "iPad8,5", "iPad8,6", "iPad8,7", "iPad8,8"
    ]

    static let a14Identifiers = [
        "iPhone13,1", "iPhone13,2", "iPhone13,3", "iPhone13,4"
    ]

    static let a15Identifiers = [
        "iPhone14,4", "iPhone14,5", "iPhone14,2", "iPhone14,3"
    ]

    static let a16Identifiers = [
        "iPhone14,7", "iPhone14,8", "iPhone15,2", "iPhone15,3"
    ]

    static let a17Identifiers = ["iPhone16,1", "iPhone16,2"]

    static var supportedIdentifiers: [String] {
        a12XIdentifiers + a14Identifiers + a15Identifiers + a16Identifiers + a17Identifiers
    }

    static var currentDeviceIdentifier: String {
        var systemInfo = utsname()
        uname(&systemInfo)
        return withUnsafeBytes(of: &systemInfo.machine) { rawBuffer in
            let bytes = rawBuffer.bindMemory(to: UInt8.self)
            let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
            return String(decoding: bytes[..<end], as: UTF8.self)
        }
    }

    static var isSupportedDevice: Bool {
        supportedIdentifiers.contains(currentDeviceIdentifier)
    }

    static var currentChip: LuminaChip {
        let id = currentDeviceIdentifier
        if a12XIdentifiers.contains(id) { return .a12x }
        if a14Identifiers.contains(id) { return .a14 }
        if a15Identifiers.contains(id) { return .a15 }
        if a16Identifiers.contains(id) { return .a16 }
        if a17Identifiers.contains(id) { return .a17 }
        return .unknown
    }

    static var deviceCategory: String {
        switch currentChip {
        case .a12x: return "iPad Pro (A12X)"
        case .a14: return "iPhone 12 Series (A14)"
        case .a15: return "iPhone 13 Series (A15)"
        case .a16: return "iPhone 14 Series (A16)"
        case .a17: return "iPhone 15 Pro (A17)"
        case .unknown: return "Unsupported Device"
        }
    }

    static var expectedKBase: UInt64? {
        switch currentChip {
        case .a12x, .a14: return 0xFFFFFFF007004000
        default: return nil
        }
    }

    static var kernelVersion: String {
        var uts = utsname()
        uname(&uts)
        return withUnsafeBytes(of: &uts.release) { rawBuffer in
            let bytes = rawBuffer.bindMemory(to: UInt8.self)
            let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
            return String(decoding: bytes[..<end], as: UTF8.self)
        }
    }
}

//
//  DeviceUtils.swift
//  Lum1na
//

import Foundation
import UIKit

// MARK: - Device Utils (single source of truth)
public enum DeviceUtils {
    public static let a14Devices = [
        "iPhone13,1", "iPhone13,2", "iPhone13,3", "iPhone13,4"
    ]

    public static let a12xDevices = [
        "iPad8,1", "iPad8,2", "iPad8,3", "iPad8,4",
        "iPad8,5", "iPad8,6", "iPad8,7", "iPad8,8",
        "iPad8,9", "iPad8,10", "iPad8,11", "iPad8,12"
    ]

    /// Raw machine identifier, e.g. "iPhone13,2"
    public static var currentDeviceIdentifier: String {
        var size = 0
        sysctlbyname("hw.machine", nil, &size, nil, 0)
        var machine = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.machine", &machine, &size, nil, 0)
        return String(cString: machine)
    }

    /// Human-readable device line for UI/debug output
    public static var currentDevice: String {
        "\(currentDeviceIdentifier) — \(deviceCategory)"
    }

    /// Silicon summary for the detected device
    public static var currentChip: String {
        switch deviceCategory {
        case "A14":  return "A14 Bionic (Firestorm/Icestorm)"
        case "A12X": return "A12X Bionic (Vortex/Tempest)"
        default:     return "Unknown"
        }
    }

    public static var isSupported: Bool {
        a14Devices.contains(currentDeviceIdentifier) ||
        a12xDevices.contains(currentDeviceIdentifier)
    }

    public static var deviceCategory: String {
        if a14Devices.contains(currentDeviceIdentifier) { return "A14" }
        if a12xDevices.contains(currentDeviceIdentifier) { return "A12X" }
        return "Unknown"
    }

    public static var osversion: String {
        var size = 0
        sysctlbyname("kern.osversion", nil, &size, nil, 0)
        guard size > 0 else { return "?" }
        var buf = [CChar](repeating: 0, count: size)
        sysctlbyname("kern.osversion", &buf, &size, nil, 0)
        return String(cString: buf)
    }

    public static var marketingVersion: String {
        UIDevice.current.systemVersion
    }

    public static var friendlyProduct: String {
        switch currentDeviceIdentifier {
        case "iPhone13,1": return "iPhone 12 mini"
        case "iPhone13,2": return "iPhone 12"
        case "iPhone13,3": return "iPhone 12 Pro"
        case "iPhone13,4": return "iPhone 12 Pro Max"
        case "iPad8,1", "iPad8,2", "iPad8,3", "iPad8,4":
            return "iPad Pro 11\""
        case "iPad8,5", "iPad8,6", "iPad8,7", "iPad8,8":
            return "iPad Pro 12.9\""
        case "iPad8,9", "iPad8,10":
            return "iPad Pro 11\" (2nd)"
        case "iPad8,11", "iPad8,12":
            return "iPad Pro 12.9\" (4th)"
        default:
            return currentDeviceIdentifier
        }
    }

    /// Sketch-style device line: "iPhone 12  update:26.5"
    public static var headerDeviceLine: String {
        "\(friendlyProduct)  update:\(marketingVersion)"
    }
}

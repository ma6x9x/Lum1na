//
//  DeviceUtils.swift
//  Lum1na
//

import Foundation

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
}

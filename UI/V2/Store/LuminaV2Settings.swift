//
//  LuminaV2Settings.swift
//  Lum1na — persisted prefs for the v2 shell (UI only).
//

import Foundation
import SwiftUI

enum TimestampMode: String, CaseIterable, Identifiable {
    case milliseconds = "Milliseconds"
    case seconds = "Seconds"
    case off = "Off"
    var id: String { rawValue }
}

enum CRTTint: String, CaseIterable, Identifiable {
    case green = "CRT Green"
    case cyan = "Cyan"
    case amber = "Amber"
    var id: String { rawValue }

    var color: Color {
        switch self {
        case .green: return LuminaV2Theme.crtGreen
        case .cyan: return LuminaV2Theme.cyan
        case .amber: return LuminaV2Theme.amber
        }
    }
}

enum ConsoleDefaultLevel: String, CaseIterable, Identifiable {
    case `default` = "Default"
    case info = "Info"
    case debug = "Debug"
    case error = "Error"
    var id: String { rawValue }
}

@MainActor
@Observable
final class LuminaV2Settings {
    var confirmBeforeRun: Bool {
        didSet { UserDefaults.standard.set(confirmBeforeRun, forKey: Keys.confirmBeforeRun) }
    }
    var pinLastSummary: Bool {
        didSet { UserDefaults.standard.set(pinLastSummary, forKey: Keys.pinLastSummary) }
    }
    var defaultGroup: TestGroup {
        didSet { UserDefaults.standard.set(defaultGroup.rawValue, forKey: Keys.defaultGroup) }
    }
    var compactBadges: Bool {
        didSet { UserDefaults.standard.set(compactBadges, forKey: Keys.compactBadges) }
    }
    var stopOnFailure: Bool {
        didSet { UserDefaults.standard.set(stopOnFailure, forKey: Keys.stopOnFailure) }
    }
    var autoAdvanceSteps: Bool {
        didSet { UserDefaults.standard.set(autoAdvanceSteps, forKey: Keys.autoAdvanceSteps) }
    }
    var liveStream: Bool {
        didSet { UserDefaults.standard.set(liveStream, forKey: Keys.liveStream) }
    }
    var bufferSize: Int {
        didSet { UserDefaults.standard.set(bufferSize, forKey: Keys.bufferSize) }
    }
    var showMilliseconds: Bool {
        didSet { UserDefaults.standard.set(showMilliseconds, forKey: Keys.showMilliseconds) }
    }
    var timestampMode: TimestampMode {
        didSet { UserDefaults.standard.set(timestampMode.rawValue, forKey: Keys.timestampMode) }
    }
    var defaultLogLevel: ConsoleDefaultLevel {
        didSet { UserDefaults.standard.set(defaultLogLevel.rawValue, forKey: Keys.defaultLogLevel) }
    }
    var crtTint: CRTTint {
        didSet { UserDefaults.standard.set(crtTint.rawValue, forKey: Keys.crtTint) }
    }
    var crtScanlines: Bool {
        didSet { UserDefaults.standard.set(crtScanlines, forKey: Keys.crtScanlines) }
    }

    private enum Keys {
        static let confirmBeforeRun = "lumina.v2.confirmBeforeRun"
        static let pinLastSummary = "lumina.v2.pinLastSummary"
        static let defaultGroup = "lumina.v2.defaultGroup"
        static let compactBadges = "lumina.v2.compactBadges"
        static let stopOnFailure = "lumina.v2.stopOnFailure"
        static let autoAdvanceSteps = "lumina.v2.autoAdvanceSteps"
        static let liveStream = "lumina.v2.liveStream"
        static let bufferSize = "lumina.v2.bufferSize"
        static let showMilliseconds = "lumina.v2.showMilliseconds"
        static let timestampMode = "lumina.v2.timestampMode"
        static let defaultLogLevel = "lumina.v2.defaultLogLevel"
        static let crtTint = "lumina.v2.crtTint"
        static let crtScanlines = "lumina.v2.crtScanlines"
    }

    init() {
        let d = UserDefaults.standard
        confirmBeforeRun = d.object(forKey: Keys.confirmBeforeRun) as? Bool ?? true
        pinLastSummary = d.object(forKey: Keys.pinLastSummary) as? Bool ?? true
        if let raw = d.string(forKey: Keys.defaultGroup), let g = TestGroup(rawValue: raw) {
            defaultGroup = g
        } else {
            defaultGroup = .probes
        }
        compactBadges = d.object(forKey: Keys.compactBadges) as? Bool ?? true
        stopOnFailure = d.object(forKey: Keys.stopOnFailure) as? Bool ?? true
        autoAdvanceSteps = d.object(forKey: Keys.autoAdvanceSteps) as? Bool ?? false
        liveStream = d.object(forKey: Keys.liveStream) as? Bool ?? true
        let buf = d.object(forKey: Keys.bufferSize) as? Int ?? 10_000
        bufferSize = max(500, min(buf, 50_000))
        let showMs = d.object(forKey: Keys.showMilliseconds) as? Bool ?? true
        showMilliseconds = showMs
        if let raw = d.string(forKey: Keys.timestampMode), let m = TimestampMode(rawValue: raw) {
            timestampMode = m
        } else {
            timestampMode = showMs ? .milliseconds : .seconds
        }
        if let raw = d.string(forKey: Keys.defaultLogLevel), let m = ConsoleDefaultLevel(rawValue: raw) {
            defaultLogLevel = m
        } else {
            defaultLogLevel = .info
        }
        if let raw = d.string(forKey: Keys.crtTint), let m = CRTTint(rawValue: raw) {
            crtTint = m
        } else {
            crtTint = .green
        }
        crtScanlines = d.object(forKey: Keys.crtScanlines) as? Bool ?? true
    }
}

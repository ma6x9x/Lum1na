//
//  LuminaV2Settings.swift
//  Lum1na — user prefs for the v2 shell (UI only).
//

import Foundation
import SwiftUI

@MainActor
@Observable
final class LuminaV2Settings {
    var confirmBeforeRun: Bool = true
    var pinLastSummary: Bool = true
    var defaultGroup: TestGroup = .probes
    var compactBadges: Bool = true
    var stopOnFailure: Bool = true
    var autoAdvanceSteps: Bool = false
    var liveStream: Bool = true
    var bufferSize: Int = 10_000
    var showMilliseconds: Bool = true
    var defaultLogLevel: ConsoleLine.LogLevel = .info
}

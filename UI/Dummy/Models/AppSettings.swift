import SwiftUI
import Observation

/// Shared, observable app settings. Appearance, Motion and the console options
/// actually drive the UI; Device / System are cosmetic dummy values.
@MainActor
@Observable
final class AppSettings {
    var appearance: AppearanceMode = .system
    var motion: MotionMode = .full
    var console: ConsoleMode = .verbose
    var consoleStyle: ConsoleStyle = .crt

    /// Cosmetic, fixed display values.
    let deviceName = "iPhone 12"
    let systemVersion = "iOS 26.5"
}

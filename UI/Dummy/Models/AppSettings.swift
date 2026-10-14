import SwiftUI
import Observation

/// Shared, observable app settings. Motion and the console options actually
/// drive the UI; Device / System are cosmetic dummy values. Appearance was
/// removed 2026-10-14 — the UI is always dark (RootView pins
/// `.preferredColorScheme(.dark)`).
@MainActor
@Observable
final class AppSettings {
    var motion: MotionMode = .full
    var console: ConsoleMode = .verbose
    var consoleStyle: ConsoleStyle = .crt

    /// Cosmetic, fixed display values.
    let deviceName = "iPhone 12"
    let systemVersion = "iOS 26.5"
}
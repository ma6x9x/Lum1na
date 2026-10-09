import SwiftUI

/// The *effective* motion level after combining the user's Motion setting with
/// the system Reduce Motion accessibility setting. Injected into the
/// environment so any view can scale its animation down or freeze it.
enum MotionLevel: Sendable {
    case full
    case subtle
    case off

    /// Continuous motion (board pulses, LEDs, CRT flicker, glitches) runs.
    var allowsContinuousMotion: Bool { self != .off }

    /// Amplitude multiplier for continuous motion.
    var amplitude: Double {
        switch self {
        case .full: 1.0
        case .subtle: 0.45
        case .off: 0.0
        }
    }
}

extension EnvironmentValues {
    /// Effective motion level for the whole UI.
    @Entry var luminaMotion: MotionLevel = .full
}

import SwiftUI

/// Spring presets tuned per the glass study (bounce kept ≤ 0.2 for normal UI).
/// `response` is the pacing; `dampingFraction` = 1 − bounce.
enum Motion {
    static let snappy = Animation.spring(response: 0.30, dampingFraction: 1.0)
    static let smooth = Animation.spring(response: 0.45, dampingFraction: 1.0)
    static let lively = Animation.spring(response: 0.50, dampingFraction: 0.85)
    static let hero = Animation.spring(response: 0.70, dampingFraction: 0.80)

    /// Swap to a short cross-fade when motion is reduced/off.
    static func adaptive(_ base: Animation, motion: MotionLevel) -> Animation {
        motion == .off ? .easeInOut(duration: 0.2) : base
    }
}

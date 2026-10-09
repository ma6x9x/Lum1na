import SwiftUI

/// Central colour palette for the Lum1na brand.
///
/// The star gradient (hot pink → violet → cyan) is shared across light and dark
/// appearances; board tones differ per appearance (see `BoardColors`).
enum Palette {
    static let magenta = Color(red: 0.98, green: 0.24, blue: 0.74)
    static let pink = Color(red: 0.96, green: 0.36, blue: 0.82)
    static let violet = Color(red: 0.58, green: 0.36, blue: 0.98)
    static let indigo = Color(red: 0.36, green: 0.30, blue: 0.95)
    static let cyan = Color(red: 0.32, green: 0.82, blue: 1.0)
    static let sky = Color(red: 0.28, green: 0.56, blue: 1.0)
    static let success = Color(red: 0.20, green: 0.84, blue: 0.48)
    static let amber = Color(red: 1.0, green: 0.67, blue: 0.16)

    /// CRT phosphor colours.
    static let phosphor = Color(red: 0.56, green: 0.94, blue: 1.0)
    static let phosphorViolet = Color(red: 0.72, green: 0.61, blue: 1.0)

    /// Diagonal gradient matching the logo: magenta (top-leading) → cyan (bottom-trailing).
    static var starGradient: LinearGradient {
        LinearGradient(
            colors: [magenta, violet, cyan],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    static var wordmarkGradient: LinearGradient {
        LinearGradient(
            colors: [magenta, violet, cyan],
            startPoint: .leading,
            endPoint: .trailing
        )
    }

    /// Samples the magenta → violet → cyan ramp at `t` (0…1); used by pixel art.
    static func starRamp(_ t: Double) -> Color {
        let t = min(max(t, 0), 1)
        return t < 0.5 ? magenta.mix(with: violet, by: t * 2) : violet.mix(with: cyan, by: (t - 0.5) * 2)
    }

    /// Near-black navy PCB base (dark) / pale silver-ice (light).
    static func boardBase(for scheme: ColorScheme) -> Color {
        scheme == .dark ? Color(red: 0.020, green: 0.024, blue: 0.059) : Color(red: 0.91, green: 0.925, blue: 0.957)
    }
}

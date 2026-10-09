import SwiftUI

/// Per-appearance PCB colours: near-black navy with violet/indigo copper in
/// dark mode, pale silver-ice with violet/cyan traces in light mode.
struct BoardColors {
    let isDark: Bool
    let base: Color
    let baseCenter: Color
    let grid: Color
    let trace: Color
    let field: Color
    let via: Color
    let pad: Color
    let icBody: Color
    let icEdge: Color
    let pin: Color
    let leg: Color
    let bus: Color
    let busGap: Color
    let ledCore: Color

    init(scheme: ColorScheme) {
        isDark = scheme == .dark
        if isDark {
            base = Palette.boardBase(for: .dark)
            baseCenter = Color(red: 0.03, green: 0.03, blue: 0.095)
            grid = Color(red: 0.47, green: 0.43, blue: 1).opacity(0.055)
            trace = Color(red: 0.38, green: 0.32, blue: 0.84).opacity(0.42)
            field = Color(red: 0.31, green: 0.27, blue: 0.75).opacity(0.34)
            via = Color(red: 0.59, green: 0.51, blue: 1).opacity(0.55)
            pad = Color(red: 0.47, green: 0.39, blue: 0.94).opacity(0.5)
            icBody = Color(red: 0.043, green: 0.04, blue: 0.11)
            icEdge = Color(red: 0.55, green: 0.47, blue: 1).opacity(0.45)
            pin = Color(red: 0.67, green: 0.63, blue: 0.9).opacity(0.55)
            leg = Color(red: 0.66, green: 0.64, blue: 0.84)
            bus = Color(red: 0.47, green: 0.39, blue: 1).opacity(0.55)
            busGap = Color(red: 0.035, green: 0.04, blue: 0.1)
            ledCore = Color(red: 0.78, green: 0.98, blue: 1)
        } else {
            base = Palette.boardBase(for: .light)
            baseCenter = Color(red: 0.933, green: 0.945, blue: 0.97)
            grid = Color(red: 0.31, green: 0.35, blue: 0.67).opacity(0.07)
            trace = Color(red: 0.47, green: 0.39, blue: 0.86).opacity(0.40)
            field = Color(red: 0.43, green: 0.43, blue: 0.78).opacity(0.30)
            via = Color(red: 0.43, green: 0.35, blue: 0.86).opacity(0.55)
            pad = Color(red: 0.43, green: 0.35, blue: 0.86).opacity(0.45)
            icBody = Color(red: 0.76, green: 0.78, blue: 0.86)
            icEdge = Color(red: 0.35, green: 0.31, blue: 0.67).opacity(0.55)
            pin = Color(red: 0.59, green: 0.59, blue: 0.75).opacity(0.9)
            leg = Color(red: 0.6, green: 0.59, blue: 0.75)
            bus = Color(red: 0.43, green: 0.35, blue: 0.9).opacity(0.55)
            busGap = Color(red: 0.9, green: 0.914, blue: 0.95)
            ledCore = Color(red: 0.16, green: 0.55, blue: 0.86)
        }
    }
}

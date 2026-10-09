import SwiftUI

/// Coloured pixel tag chip: `[ OK ]` green, `[ .. ]` cyan, `[WARN]` amber, `[INFO]` violet.
struct TagChipView: View {
    let tag: LogTag
    var style: ConsoleStyle

    var body: some View {
        Text(tag.chipText)
            .foregroundStyle(foreground)
            .padding(.horizontal, 3)
            .background(background, in: .rect)
            .shadow(color: style == .crt ? background.opacity(0.9) : .clear, radius: 3)
    }

    private var background: Color {
        switch tag {
        case .ok: Color(red: 0.12, green: 0.56, blue: 0.31)
        case .busy: Color(red: 0.06, green: 0.37, blue: 0.48)
        case .warn: Color(red: 0.6, green: 0.39, blue: 0.06)
        case .info: Color(red: 0.29, green: 0.18, blue: 0.6)
        }
    }

    private var foreground: Color {
        switch tag {
        case .ok: Color(red: 0.79, green: 1, blue: 0.85)
        case .busy: Color(red: 0.78, green: 0.96, blue: 1)
        case .warn: Color(red: 1, green: 0.9, blue: 0.72)
        case .info: Color(red: 0.89, green: 0.85, blue: 1)
        }
    }
}

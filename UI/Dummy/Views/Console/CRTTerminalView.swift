import SwiftUI

/// Reusable retro terminal surface for the console card and sheet. In CRT
/// style the content gets a phosphor glow (a tight and a wide accent-coloured
/// blur of the glyphs), then the tube overlay, inside a curved bezel. Clean
/// style keeps the dark screen and drops every effect.
struct CRTTerminalView<Content: View>: View {
    var style: ConsoleStyle
    var cornerRadius: CGFloat = 14
    @ViewBuilder var content: Content

    @Environment(\.colorScheme) private var scheme

    private var crt: Bool { style == .crt }

    var body: some View {
        let screen = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        content
            .shadow(color: crt ? Palette.phosphor.opacity(0.9) : .clear, radius: crt ? 1 : 0)
            .shadow(color: crt ? Palette.cyan.opacity(0.5) : .clear, radius: crt ? 5 : 0)
            .background {
                screen.fill(RadialGradient(
                    colors: [Color(red: 0.04, green: 0.08, blue: 0.15), Color(red: 0.02, green: 0.035, blue: 0.07), Color(red: 0.008, green: 0.012, blue: 0.03)],
                    center: UnitPoint(x: 0.5, y: 0.45), startRadius: 0, endRadius: 320
                ))
            }
            .overlay {
                if crt { CRTOverlayView() }
            }
            .clipShape(screen)
            .overlay {
                // Curved-glass edge: dark inner falloff plus a faint phosphor rim.
                // Decorative only — a stroked shape still hit-tests its fill, which
                // was swallowing the expand control.
                ZStack {
                    screen.strokeBorder(.black.opacity(0.8), lineWidth: 6).blur(radius: 6).clipShape(screen)
                    screen.strokeBorder(Palette.phosphor.opacity(0.18), lineWidth: 0.75)
                }
                .allowsHitTesting(false)
            }
            .padding(5)
            .background {
                RoundedRectangle(cornerRadius: cornerRadius + 5, style: .continuous)
                    .fill(LinearGradient(colors: bezelColors, startPoint: .topLeading, endPoint: .bottomTrailing))
                    .shadow(color: .black.opacity(scheme == .dark ? 0.45 : 0.18), radius: 12, y: 8)
            }
            .overlay {
                RoundedRectangle(cornerRadius: cornerRadius + 5, style: .continuous)
                    .strokeBorder(.white.opacity(scheme == .dark ? 0.08 : 0.7), lineWidth: 1)
            }
    }

    private var bezelColors: [Color] {
        scheme == .dark
            ? [Color(red: 0.125, green: 0.125, blue: 0.23), Color(red: 0.043, green: 0.043, blue: 0.086), Color(red: 0.086, green: 0.086, blue: 0.165)]
            : [Color(red: 0.81, green: 0.83, blue: 0.89), Color(red: 0.68, green: 0.7, blue: 0.79), Color(red: 0.78, green: 0.79, blue: 0.86)]
    }
}

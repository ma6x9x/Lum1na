import SwiftUI

/// Reusable retro terminal surface for the console card and the fullscreen
/// log panel. The tube itself stays dark (phosphor + scanlines); the outer
/// plate is the liquid-glass slab so the board shows through the rim.
struct CRTTerminalView<Content: View>: View {
    var style: ConsoleStyle
    var cornerRadius: CGFloat = 14
    @ViewBuilder var content: Content

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
            .padding(6)
            .glassSurface(
                RoundedRectangle(cornerRadius: cornerRadius + 6, style: .continuous),
                tint: Palette.violet.opacity(0.55),
                interactive: false
            )
            .fresnelRim(
                RoundedRectangle(cornerRadius: cornerRadius + 6, style: .continuous),
                intensity: 0.7,
                glowWidth: 6
            )
    }
}

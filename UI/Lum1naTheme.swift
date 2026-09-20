import SwiftUI

enum Lum1naPalette {
    static let field = Color(red: 0.027, green: 0.024, blue: 0.059) // #07060F
    static let magenta = Color(red: 0.92, green: 0.28, blue: 0.72)
    static let violet = Color(red: 0.56, green: 0.35, blue: 0.98)
    static let ice = Color(red: 0.45, green: 0.85, blue: 0.98)
    static let rain = Color(red: 0.55, green: 0.62, blue: 0.78)

    static var wordmarkGradient: LinearGradient {
        LinearGradient(
            colors: [magenta, .white, ice],
            startPoint: .leading,
            endPoint: .trailing
        )
    }

    static var ringGradient: AngularGradient {
        AngularGradient(
            colors: [magenta, violet, ice, magenta],
            center: .center
        )
    }
}

/// Liquid-glass look using materials (works on Xcode 16 / iOS 16+).
/// Native `.glassEffect` can be reintroduced when CI builds with an iOS 26 SDK.
struct LiquidGlassCard<Content: View>: View {
    var cornerRadius: CGFloat = 22
    @ViewBuilder var content: () -> Content

    var body: some View {
        content()
            .background(glassBackground)
            .clipShape(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .stroke(
                        LinearGradient(
                            colors: [
                                Color.white.opacity(0.35),
                                Lum1naPalette.magenta.opacity(0.35),
                                Lum1naPalette.ice.opacity(0.25),
                                Color.white.opacity(0.08)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 1
                    )
            )
    }

    private var glassBackground: some View {
        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
            .fill(.ultraThinMaterial)
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(Color.white.opacity(0.06))
            )
    }
}

struct LiquidGlassCapsuleButtonStyle: ButtonStyle {
    var prominent: Bool = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 16, weight: .semibold, design: .rounded))
            .foregroundStyle(.white)
            .padding(.horizontal, 22)
            .padding(.vertical, 14)
            .frame(maxWidth: .infinity)
            .background(background(isPressed: configuration.isPressed))
            .clipShape(Capsule())
            .overlay(
                Capsule()
                    .stroke(
                        LinearGradient(
                            colors: [
                                Lum1naPalette.magenta.opacity(0.9),
                                Lum1naPalette.ice.opacity(0.9)
                            ],
                            startPoint: .leading,
                            endPoint: .trailing
                        ),
                        lineWidth: prominent ? 1.4 : 1
                    )
            )
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
    }

    @ViewBuilder
    private func background(isPressed: Bool) -> some View {
        if prominent {
            LinearGradient(
                colors: [
                    Lum1naPalette.violet.opacity(isPressed ? 0.85 : 1),
                    Lum1naPalette.magenta.opacity(isPressed ? 0.55 : 0.75)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        } else {
            Capsule().fill(.ultraThinMaterial)
        }
    }
}

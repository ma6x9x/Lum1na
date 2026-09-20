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

// MARK: - Fake liquid glass (inspired by liquid (gl)ass stock look)
//
// Public-API approximation of the liquidass recipe:
//   1. ultra-thin material blur (stand-in for CABackdropLayer)
//   2. continuous corner curve
//   3. soft separator edge (~0.16 alpha)
//   4. angled specular rim (white → clear → soft bottom catch)
//   5. light frost wash so it reads like real glass, not a flat card

private enum LiquidAssGlass {
    /// Matches liquidass specular stops: peak, soft, clear, clear, shadow, catch.
    static func specularColors(maxAlpha: Double = 0.35) -> [Color] {
        [
            Color.white.opacity(maxAlpha * 0.28),
            Color.white.opacity(maxAlpha * 0.10),
            Color.clear,
            Color.clear,
            Color.black.opacity(maxAlpha * 0.04),
            Color.white.opacity(maxAlpha * 0.12)
        ]
    }

    static let specularStops: [CGFloat] = [0.0, 0.12, 0.34, 0.66, 0.88, 1.0]

    /// ~ -45° like liquidass default specular angle.
    static var specularGradient: LinearGradient {
        LinearGradient(
            stops: zip(specularStops, specularColors()).map { Gradient.Stop(color: $0.1, location: $0.0) },
            startPoint: UnitPoint(x: 0.15, y: 0.05),
            endPoint: UnitPoint(x: 0.85, y: 0.95)
        )
    }

    static var edgeStroke: Color {
        Color.white.opacity(0.16)
    }

    static var frostWash: Color {
        Color.white.opacity(0.07)
    }
}

struct LiquidGlassCard<Content: View>: View {
    var cornerRadius: CGFloat = 22
    @ViewBuilder var content: () -> Content

    var body: some View {
        content()
            .background { glassFill }
            .clipShape(shape)
            .overlay { specularRim }
            .overlay { edgeRim }
            .shadow(color: Color.black.opacity(0.22), radius: 18, y: 8)
    }

    private var shape: RoundedRectangle {
        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
    }

    private var glassFill: some View {
        shape
            .fill(.ultraThinMaterial)
            .background(shape.fill(LiquidAssGlass.frostWash))
            .overlay {
                // Top-weighted specular wash (liquidass edge highlight).
                shape.fill(
                    LinearGradient(
                        colors: [
                            Color.white.opacity(0.18),
                            Color.white.opacity(0.04),
                            Color.clear
                        ],
                        startPoint: .top,
                        endPoint: UnitPoint(x: 0.5, y: 0.55)
                    )
                )
                .allowsHitTesting(false)
            }
    }

    private var specularRim: some View {
        shape
            .strokeBorder(LiquidAssGlass.specularGradient, lineWidth: 1.1)
            .allowsHitTesting(false)
    }

    private var edgeRim: some View {
        shape
            .strokeBorder(LiquidAssGlass.edgeStroke, lineWidth: 0.5)
            .allowsHitTesting(false)
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
            .background { capsuleFill(isPressed: configuration.isPressed) }
            .clipShape(Capsule(style: .continuous))
            .overlay {
                Capsule(style: .continuous)
                    .strokeBorder(LiquidAssGlass.specularGradient, lineWidth: prominent ? 1.25 : 1.0)
            }
            .overlay {
                Capsule(style: .continuous)
                    .strokeBorder(LiquidAssGlass.edgeStroke, lineWidth: 0.5)
            }
            .shadow(color: Color.black.opacity(prominent ? 0.28 : 0.16), radius: 12, y: 5)
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
    }

    @ViewBuilder
    private func capsuleFill(isPressed: Bool) -> some View {
        if prominent {
            Capsule(style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [
                            Lum1naPalette.violet.opacity(isPressed ? 0.85 : 1),
                            Lum1naPalette.magenta.opacity(isPressed ? 0.55 : 0.78)
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .overlay {
                    Capsule(style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [Color.white.opacity(0.22), Color.clear],
                                startPoint: .top,
                                endPoint: .center
                            )
                        )
                }
        } else {
            Capsule(style: .continuous)
                .fill(.ultraThinMaterial)
                .background(Capsule(style: .continuous).fill(LiquidAssGlass.frostWash))
                .overlay {
                    Capsule(style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [Color.white.opacity(0.16), Color.clear],
                                startPoint: .top,
                                endPoint: UnitPoint(x: 0.5, y: 0.6)
                            )
                        )
                }
        }
    }
}

/// Circular glass disc — same liquidass specular recipe for the star ring.
struct LiquidGlassDisc: View {
    var diameter: CGFloat = 158

    var body: some View {
        Circle()
            .fill(.ultraThinMaterial)
            .background(Circle().fill(LiquidAssGlass.frostWash))
            .overlay {
                Circle().fill(
                    LinearGradient(
                        colors: [Color.white.opacity(0.20), Color.clear],
                        startPoint: .top,
                        endPoint: .center
                    )
                )
            }
            .overlay {
                Circle().strokeBorder(LiquidAssGlass.specularGradient, lineWidth: 1.1)
            }
            .overlay {
                Circle().strokeBorder(LiquidAssGlass.edgeStroke, lineWidth: 0.5)
            }
            .frame(width: diameter, height: diameter)
            .opacity(0.92)
    }
}

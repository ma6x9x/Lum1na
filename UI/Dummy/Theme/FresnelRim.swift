import SwiftUI

/// Pure-SwiftUI specular + Fresnel rim (no Metal), adapted from the Lum1na
/// glass study. Reflectance rises toward grazing angles, so a glass edge looks
/// brighter than its face and brightest toward the light. Three cheap layers:
/// a wide blurred inner glow, a crisp specular line, and a hairline contact edge.
/// `.plusLighter` makes highlights add light like real reflections.
struct FresnelRim<S: InsettableShape>: ViewModifier {
    var shape: S
    /// Angle the light comes from, degrees (0 = trailing, 90 = bottom).
    var lightAngle: Double = -135
    var intensity: Double = 1
    var glowWidth: CGFloat = 10

    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.colorScheme) private var scheme

    private var rimGradient: AngularGradient {
        let hi = 0.85 * intensity
        let lo = 0.30 * intensity
        return AngularGradient(
            stops: [
                .init(color: .white.opacity(hi), location: 0.00),
                .init(color: .white.opacity(0.05), location: 0.20),
                .init(color: .white.opacity(lo), location: 0.50),
                .init(color: .white.opacity(0.05), location: 0.80),
                .init(color: .white.opacity(hi), location: 1.00)
            ],
            center: .center,
            angle: .degrees(lightAngle)
        )
    }

    func body(content: Content) -> some View {
        content
            .overlay {
                shape
                    .strokeBorder(rimGradient, lineWidth: glowWidth)
                    .blur(radius: glowWidth * 0.6)
                    .opacity(0.45 * intensity)
                    .clipShape(shape)
                    .blendMode(.plusLighter)
                    .allowsHitTesting(false)
            }
            .overlay {
                shape
                    .strokeBorder(rimGradient, lineWidth: contrast == .increased ? 1.5 : 1)
                    .blendMode(.plusLighter)
                    .allowsHitTesting(false)
            }
            .overlay {
                shape
                    .stroke(
                        Color.black.opacity(
                            contrast == .increased ? 0.35 : (scheme == .dark ? 0.22 : 0.08)
                        ),
                        lineWidth: 0.5
                    )
                    .allowsHitTesting(false)
            }
    }
}

extension View {
    /// Applies a specular/Fresnel rim to a glass edge of the given shape.
    func fresnelRim<S: InsettableShape>(
        _ shape: S,
        lightAngle: Double = -135,
        intensity: Double = 1,
        glowWidth: CGFloat = 10
    ) -> some View {
        modifier(FresnelRim(shape: shape, lightAngle: lightAngle, intensity: intensity, glowWidth: glowWidth))
    }
}

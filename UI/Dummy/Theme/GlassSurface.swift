import SwiftUI
import UIKit

/// Applies a stock iOS 26 Liquid Glass surface to content, falling back to the
/// liquid-glass study recipe on Xcode 16.4 (material, tint, inner shadow,
/// Fresnel rim, grain). Opaque when Reduce Transparency is on.
struct GlassSurface<S: InsettableShape>: ViewModifier {
    var shape: S
    var tint: Color?
    var interactive: Bool

    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorScheme) private var scheme

    func body(content: Content) -> some View {
        if reduceTransparency {
            content.background(solidFill, in: shape)
        } else {
            #if compiler(>=6.2)
            if #available(iOS 26.0, *) {
                native(content)
            } else {
                content.modifier(StudyGlassFallback(shape: shape, tint: tint))
            }
            #else
            content.modifier(StudyGlassFallback(shape: shape, tint: tint))
            #endif
        }
    }

    #if compiler(>=6.2)
    @available(iOS 26.0, *)
    private func native(_ content: Content) -> some View {
        content.glassEffect(nativeGlass, in: shape)
    }

    @available(iOS 26.0, *)
    private var nativeGlass: Glass {
        var value = Glass.regular
        if let tint { value = value.tint(tint) }
        if interactive { value = value.interactive() }
        return value
    }
    #endif

    private var solidFill: Color {
        let base = scheme == .dark ? Color(white: 0.12) : Color(white: 0.96)
        guard let tint else { return base }
        return base.mix(with: tint, by: 0.22)
    }
}

extension View {
    /// Convenience for a glass surface clipped to `shape`.
    func glassSurface(
        _ shape: some InsettableShape,
        tint: Color? = nil,
        interactive: Bool = false
    ) -> some View {
        modifier(GlassSurface(shape: shape, tint: tint, interactive: interactive))
    }

    /// Matched-geometry glass id on Xcode 26. A no-op on the 16.4 toolchain.
    @ViewBuilder
    func luminaGlassID(_ id: String, in namespace: Namespace.ID) -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26.0, *) {
            self.glassEffectID(id, in: namespace)
                .glassEffectTransition(.matchedGeometry)
        } else {
            self
        }
        #else
        self
        #endif
    }

    @ViewBuilder
    func luminaGlassButton(prominent: Bool) -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26.0, *) {
            if prominent {
                self.buttonStyle(.glassProminent)
            } else {
                self.buttonStyle(.glass)
            }
        } else {
            self.buttonStyle(StudyGlassButtonStyle(prominent: prominent))
        }
        #else
        self.buttonStyle(StudyGlassButtonStyle(prominent: prominent))
        #endif
    }
}

/// Groups glass siblings on Xcode 26. On 16.4 the children draw their own fallback.
struct LuminaGlassCluster<Content: View>: View {
    var spacing: CGFloat = 8
    @ViewBuilder var content: () -> Content

    var body: some View {
        #if compiler(>=6.2)
        if #available(iOS 26.0, *) {
            GlassEffectContainer(spacing: spacing, content: content)
        } else {
            content()
        }
        #else
        content()
        #endif
    }
}

/// Liquid-glass study fallback: material, tint wash, inner shadow, 0.5 pt
/// Fresnel rim + ~3 pt sheen, grain, soft shadow.
private struct StudyGlassFallback<S: InsettableShape>: ViewModifier {
    var shape: S
    var tint: Color?

    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.colorScheme) private var scheme

    func body(content: Content) -> some View {
        content
            .background { backdrop }
            .overlay { innerShadow }
            .overlay { rim }
            .overlay { grain }
            .clipShape(shape)
            .shadow(color: .black.opacity(scheme == .dark ? 0.32 : 0.12), radius: 16, y: 8)
    }

    @ViewBuilder private var backdrop: some View {
        if reduceTransparency {
            shape.fill(scheme == .dark ? Color(white: 0.12) : Color(white: 0.96))
        } else {
            ZStack {
                shape.fill(.ultraThinMaterial)
                shape.fill((tint ?? Palette.violet).opacity(scheme == .dark ? 0.10 : 0.06))
                shape.fill(LinearGradient(
                    colors: [Color.white.opacity(0.50), Color.white.opacity(0.16), .clear],
                    startPoint: .top,
                    endPoint: UnitPoint(x: 0.5, y: 0.22)
                ))
            }
        }
    }

    private var innerShadow: some View {
        shape
            .stroke(Color.black.opacity(scheme == .dark ? 0.45 : 0.18), lineWidth: 6)
            .blur(radius: 6)
            .offset(y: 3)
            .mask(shape)
            .allowsHitTesting(false)
    }

    private var rim: some View {
        let boost = contrast == .increased
        return ZStack {
            shape.strokeBorder(
                AngularGradient(
                    stops: [
                        .init(color: .white.opacity(0.75), location: 0.0),
                        .init(color: .white.opacity(0.06), location: 0.22),
                        .init(color: .white.opacity(0.28), location: 0.50),
                        .init(color: .white.opacity(0.06), location: 0.78),
                        .init(color: .white.opacity(0.75), location: 1.0)
                    ],
                    center: .center,
                    angle: .degrees(-135)
                ),
                lineWidth: boost ? 1.5 : 1
            )
            .blendMode(.plusLighter)
            shape.strokeBorder(Color.white.opacity(boost ? 0.7 : 0.30), lineWidth: 0.5)
        }
        .allowsHitTesting(false)
    }

    private var grain: some View {
        Image(uiImage: NoiseTile.image)
            .resizable(resizingMode: .tile)
            .opacity(reduceTransparency ? 0 : 0.035)
            .blendMode(.overlay)
            .clipShape(shape)
            .allowsHitTesting(false)
            .accessibilityHidden(true)
    }
}

private struct StudyGlassButtonStyle: ButtonStyle {
    var prominent: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(.white)
            .background {
                ZStack {
                    Capsule().fill(.ultraThinMaterial)
                    Capsule().fill(Palette.violet.opacity(prominent ? 0.45 : 0.12))
                    Capsule().fill(LinearGradient(
                        colors: [Color.white.opacity(0.50), Color.white.opacity(0.16), .clear],
                        startPoint: .top,
                        endPoint: UnitPoint(x: 0.5, y: 0.28)
                    ))
                }
            }
            .overlay {
                Capsule()
                    .strokeBorder(Color.white.opacity(0.30), lineWidth: 0.5)
            }
            .shadow(color: Palette.violet.opacity(prominent ? 0.45 : 0.18), radius: prominent ? 12 : 6)
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
    }
}

/// 96×96 monochrome noise, made once and cached (tiling cost is negligible).
enum NoiseTile {
    static let image: UIImage = {
        let size = CGSize(width: 96, height: 96)
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        return UIGraphicsImageRenderer(size: size, format: format).image { ctx in
            var rng = SystemRandomNumberGenerator()
            for y in 0..<Int(size.height) {
                for x in 0..<Int(size.width) {
                    let v = CGFloat(UInt8.random(in: 0...255, using: &rng)) / 255
                    UIColor(white: v, alpha: 1).setFill()
                    ctx.fill(CGRect(x: x, y: y, width: 1, height: 1))
                }
            }
        }
    }()
}

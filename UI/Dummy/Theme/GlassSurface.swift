import SwiftUI

/// Applies a stock iOS 26 Liquid Glass surface to content, falling back to an
/// opaque tinted fill when Reduce Transparency is on (per the glass study and
/// the accessibility skill).
struct GlassSurface<S: Shape>: ViewModifier {
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
        _ shape: some Shape,
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

/// Liquid-glass study fallback: material, tint wash, 0.5 pt rim, soft shadow.
/// Opaque when Reduce Transparency is on.
private struct StudyGlassFallback<S: Shape>: ViewModifier {
    var shape: S
    var tint: Color?

    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.colorScheme) private var scheme

    func body(content: Content) -> some View {
        content
            .background { backdrop }
            .overlay { rim }
            .clipShape(shape)
            .shadow(color: .black.opacity(scheme == .dark ? 0.32 : 0.12), radius: 16, y: 8)
    }

    @ViewBuilder private var backdrop: some View {
        if reduceTransparency {
            shape.fill(scheme == .dark ? Color(white: 0.12) : Color(white: 0.96))
        } else {
            ZStack {
                shape.fill(.ultraThinMaterial)
                shape.fill((tint ?? .white).opacity(scheme == .dark ? 0.10 : 0.06))
                shape.fill(LinearGradient(
                    colors: [Color.white.opacity(0.10), .clear],
                    startPoint: .top,
                    endPoint: .center
                ))
            }
        }
    }

    private var rim: some View {
        let alpha = contrast == .increased ? 0.7 : 0.30
        return shape.stroke(Color.white.opacity(alpha), lineWidth: 0.5)
    }
}

private struct StudyGlassButtonStyle: ButtonStyle {
    var prominent: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(.white)
            .background {
                Capsule().fill(.ultraThinMaterial)
                Capsule().fill(Palette.violet.opacity(prominent ? 0.45 : 0.12))
            }
            .overlay(Capsule().strokeBorder(Color.white.opacity(0.30), lineWidth: 0.5))
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
    }
}

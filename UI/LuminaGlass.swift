import SwiftUI

extension View {
    func luminaGlassCapsule() -> some View {
        modifier(LuminaGlassCap())
    }

    /// Interactive by default (pads, CTAs, chips). Pass `false` for the
    /// console plate so scrolling does not squash the glass.
    func luminaGlassRect(_ radius: CGFloat = 16, interactive: Bool = true) -> some View {
        modifier(LuminaGlassBox(radius: radius, interactive: interactive))
    }
}

private let luminaGlassSolid = Color(hex: "#1A2238")

private struct LuminaGlassCap: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        if reduceTransparency {
            content
                .background(Capsule().fill(luminaGlassSolid))
                .overlay(Capsule().strokeBorder(Color.white.opacity(0.30), lineWidth: 0.5))
        } else {
            #if compiler(>=6.2)
            if #available(iOS 26.0, *) {
                content.glassEffect(.regular.interactive(), in: Capsule())
            } else {
                fallbackCap(content)
            }
            #else
            fallbackCap(content)
            #endif
        }
    }

    private func fallbackCap(_ content: Content) -> some View {
        content
            .background {
                ZStack {
                    Capsule().fill(.ultraThinMaterial)
                    Capsule().fill(Color.white.opacity(0.06))
                    Capsule()
                        .fill(
                            LinearGradient(
                                colors: [Color.white.opacity(0.50), Color.white.opacity(0.16), .clear],
                                startPoint: .top,
                                endPoint: UnitPoint(x: 0.5, y: 0.22)
                            )
                        )
                        .mask(
                            LinearGradient(
                                colors: [.clear, .white, .white, .clear],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                }
            }
            .overlay(Capsule().strokeBorder(Color.white.opacity(0.30), lineWidth: 0.5))
            .shadow(color: Color.black.opacity(0.32), radius: 24, y: 10)
    }
}

private struct LuminaGlassBox: ViewModifier {
    var radius: CGFloat
    var interactive: Bool
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        if reduceTransparency {
            content
                .background(
                    RoundedRectangle(cornerRadius: radius, style: .continuous)
                        .fill(luminaGlassSolid)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: radius, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.30), lineWidth: 0.5)
                )
        } else {
            #if compiler(>=6.2)
            if #available(iOS 26.0, *) {
                native(content)
            } else {
                fallbackBox(content)
            }
            #else
            fallbackBox(content)
            #endif
        }
    }

    #if compiler(>=6.2)
    @available(iOS 26.0, *)
    @ViewBuilder
    private func native(_ content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: radius, style: .continuous)
        if interactive {
            content.glassEffect(.regular.interactive(), in: shape)
        } else {
            content.glassEffect(.regular, in: shape)
        }
    }
    #endif

    private func fallbackBox(_ content: Content) -> some View {
        content
            .background {
                ZStack {
                    RoundedRectangle(cornerRadius: radius, style: .continuous)
                        .fill(.ultraThinMaterial)
                    RoundedRectangle(cornerRadius: radius, style: .continuous)
                        .fill(Color.white.opacity(0.06))
                    RoundedRectangle(cornerRadius: radius, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [Color.white.opacity(0.50), Color.white.opacity(0.16), .clear],
                                startPoint: .top,
                                endPoint: UnitPoint(x: 0.5, y: 0.22)
                            )
                        )
                        .mask(
                            LinearGradient(
                                colors: [.clear, .white, .white, .clear],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                }
            }
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.30), lineWidth: 0.5)
            )
            .shadow(color: Color.black.opacity(0.32), radius: 24, y: 10)
    }
}

import SwiftUI

extension View {
    func luminaGlassCapsule() -> some View {
        modifier(LuminaGlassCap())
    }

    func luminaGlassRect(_ radius: CGFloat = 16) -> some View {
        modifier(LuminaGlassBox(radius: radius))
    }
}

private struct LuminaGlassCap: ViewModifier {
    func body(content: Content) -> some View {
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

    private func fallbackCap(_ content: Content) -> some View {
        content
            .background {
                Capsule()
                    .fill(.ultraThinMaterial)
                    .overlay(
                        Capsule().fill(
                            LinearGradient(
                                colors: [Color.white.opacity(0.28), Color.white.opacity(0.04)],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                    )
            }
            .overlay(Capsule().stroke(Color.white.opacity(0.38), lineWidth: 0.8))
            .shadow(color: Color.black.opacity(0.35), radius: 10, y: 4)
    }
}

private struct LuminaGlassBox: ViewModifier {
    var radius: CGFloat

    func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26.0, *) {
            content.glassEffect(
                .regular.interactive(),
                in: RoundedRectangle(cornerRadius: radius, style: .continuous)
            )
        } else {
            fallbackBox(content)
        }
        #else
        fallbackBox(content)
        #endif
    }

    private func fallbackBox(_ content: Content) -> some View {
        content
            .background {
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .fill(.ultraThinMaterial)
                    .overlay(
                        RoundedRectangle(cornerRadius: radius, style: .continuous)
                            .fill(
                                LinearGradient(
                                    colors: [Color.white.opacity(0.22), Color.white.opacity(0.03)],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                    )
            }
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .stroke(Color.white.opacity(0.32), lineWidth: 0.8)
            )
            .shadow(color: Color.black.opacity(0.4), radius: 14, y: 6)
    }
}

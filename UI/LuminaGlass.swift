import SwiftUI

/// Liquid-glass look that compiles on the CI Xcode 16.4 SDK.
/// On-device iOS 26 still gets a real material; we do not call
/// `.glassEffect()` here because that symbol is Xcode 26-only.
extension View {
    func luminaGlassCapsule() -> some View {
        self
            .background(.ultraThinMaterial, in: Capsule())
            .overlay(Capsule().stroke(Color.white.opacity(0.22), lineWidth: 0.8))
    }

    func luminaGlassRect(_ radius: CGFloat = 16) -> some View {
        self
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .stroke(Color.white.opacity(0.18), lineWidth: 0.8)
            )
    }
}

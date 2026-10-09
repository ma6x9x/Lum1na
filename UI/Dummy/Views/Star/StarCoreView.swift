import SwiftUI

/// The glowing gradient star itself (vector), with layered glow and a white-hot
/// core. `intensity` (0…1+) brightens the glow as the run powers up.
struct StarCoreView: View {
    var intensity: Double = 0.5

    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private let star = LuminaStarShape()

    var body: some View {
        ZStack {
            // Outer bloom.
            star
                .fill(Palette.starGradient)
                .blur(radius: 26)
                .scaleEffect(1.18)
                .opacity((reduceTransparency ? 0.25 : 0.5) + 0.35 * intensity)

            // Mid glow.
            star
                .fill(Palette.starGradient)
                .blur(radius: 9)
                .opacity(0.65 + 0.25 * intensity)

            // Crisp star body.
            star
                .fill(Palette.starGradient)

            // White-hot core.
            star
                .fill(
                    RadialGradient(
                        colors: [.white, .white.opacity(0.0)],
                        center: .center,
                        startRadius: 0,
                        endRadius: 60
                    )
                )
                .blendMode(.plusLighter)
                .opacity(0.7 + 0.3 * intensity)
        }
        .compositingGroup()
    }
}

#Preview("Star core") {
    StarCoreView(intensity: 1)
        .frame(width: 220, height: 220)
        .padding(40)
        .background(.black)
}

import SwiftUI

/// The central microchip: a dark package with a glassy specular top (a glass
/// gradient plus the Fresnel rim, since the chip is content, not a control),
/// a fine die pattern, and the glowing Lum1na star as its die.
struct MicrochipView: View {
    var size: CGFloat
    /// 0…1 star brightness (rises per completed stage).
    var intensity: Double
    /// 0…1 success flare.
    var flare: Double
    /// Gentle breathing scale (1 when motion is off).
    var breathe: Double

    private var shape: RoundedRectangle { RoundedRectangle(cornerRadius: size * 0.13, style: .continuous) }

    var body: some View {
        ZStack {
            shape
                .fill(LinearGradient(
                    colors: [Color(red: 0.11, green: 0.09, blue: 0.25), Color(red: 0.05, green: 0.045, blue: 0.13), Color(red: 0.035, green: 0.03, blue: 0.094)],
                    startPoint: .topLeading, endPoint: .bottomTrailing
                ))
                .shadow(color: .black.opacity(0.6), radius: 14, y: 8)
            ChipDieView()
                .padding(size * 0.12)
            Circle()
                .fill(.white.opacity(0.5))
                .frame(width: 5, height: 5)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .padding(9)
            Text("LUM1NA·A14")
                .font(.custom(TerminalFont.pixelFontName, size: 9, relativeTo: .caption2))
                .tracking(2)
                .foregroundStyle(Palette.phosphorViolet.opacity(0.55))
                .frame(maxHeight: .infinity, alignment: .bottom)
                .padding(.bottom, 4)
                .dynamicTypeSize(...DynamicTypeSize.large)
            StarCoreView(intensity: intensity + 0.4 * flare)
                .frame(width: size * 1.02, height: size * 1.02)
                .scaleEffect(breathe * (1 + 0.16 * flare))
            glassTop
            flareBloom
        }
        .frame(width: size, height: size)
        .overlay { shape.strokeBorder(Color(red: 0.67, green: 0.59, blue: 1).opacity(0.35), lineWidth: 1) }
        .fresnelRim(shape, intensity: 0.8, glowWidth: 8)
        .accessibilityHidden(true)
    }

    private var glassTop: some View {
        shape
            .fill(LinearGradient(
                stops: [
                    .init(color: .white.opacity(0.22), location: 0),
                    .init(color: .white.opacity(0.04), location: 0.28),
                    .init(color: .clear, location: 0.45),
                    .init(color: .clear, location: 0.7),
                    .init(color: Palette.cyan.opacity(0.10), location: 1)
                ],
                startPoint: .topLeading, endPoint: .bottomTrailing
            ))
            .allowsHitTesting(false)
    }

    private var flareBloom: some View {
        Circle()
            .fill(RadialGradient(
                colors: [.white.opacity(0.95), Palette.violet.opacity(0.5), .clear],
                center: .center, startRadius: 0, endRadius: 30 + 100 * flare
            ))
            .frame(width: 60 + 200 * flare, height: 60 + 200 * flare)
            .opacity(0.3 * intensity + 0.6 * flare)
            .blendMode(.plusLighter)
            .allowsHitTesting(false)
    }
}

#Preview("Chip") {
    MicrochipView(size: 136, intensity: 0.7, flare: 0, breathe: 1)
        .padding(60)
        .background(Color(red: 0.02, green: 0.024, blue: 0.06))
}

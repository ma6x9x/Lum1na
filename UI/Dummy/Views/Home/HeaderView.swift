import SwiftUI

/// Centered LUM1NA wordmark with the gradient star under it.
/// Settings stays on the trailing edge so the title remains centered.
struct HeaderView: View {
    var onSettings: () -> Void

    var body: some View {
        ZStack {
            VStack(spacing: 6) {
                Text("LUM1NA")
                    .font(.system(size: 32, weight: .light))
                    .tracking(8)
                    .foregroundStyle(.white)
                    .accessibilityAddTraits(.isHeader)
                LuminaStarShape()
                    .fill(Palette.starGradient)
                    .frame(width: 22, height: 28)
                    .shadow(color: Palette.magenta.opacity(0.7), radius: 6)
                    .shadow(color: Palette.cyan.opacity(0.6), radius: 8)
                    .accessibilityHidden(true)
            }
            .frame(maxWidth: .infinity)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Lum1na")

            HStack {
                Spacer()
                Button("Settings", systemImage: "gearshape", action: onSettings)
                    .labelStyle(.iconOnly)
                    .font(.body.weight(.semibold))
                    .frame(width: 44, height: 44)
                    .luminaGlassButton(prominent: false)
                    .tint(Palette.violet)
            }
        }
    }
}

#Preview("Header – Dark") {
    HeaderView(onSettings: {})
        .padding()
        .background(.black)
        .preferredColorScheme(.dark)
}

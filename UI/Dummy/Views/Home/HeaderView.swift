import SwiftUI

/// Centered LUM1NA wordmark with the gradient star under it.
/// Settings stays on the trailing edge so the title remains centered.
/// Tracking is pulled back by the same amount so the glyphs sit on the
/// optical center (SwiftUI includes the trailing gap in the layout width).
struct HeaderView: View {
    var showsBrand: Bool = true
    var showsDone: Bool = false
    var onSettings: () -> Void
    var onDone: () -> Void = {}

    var body: some View {
        ZStack {
            if showsBrand {
                VStack(spacing: 6) {
                    Text("LUM1NA")
                        .font(.system(size: 32, weight: .light))
                        .tracking(8)
                        .padding(.trailing, -8)
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
            }

            HStack {
                Spacer()
                if showsDone {
                    Button("Done", action: onDone)
                        .font(.body.weight(.semibold))
                        .padding(.horizontal, 16)
                        .frame(height: 36)
                        .luminaGlassButton(prominent: true)
                        .tint(Palette.violet)
                } else {
                    Button("Settings", systemImage: "gearshape", action: onSettings)
                        .labelStyle(.iconOnly)
                        .font(.body.weight(.semibold))
                        .frame(width: 44, height: 44)
                        .luminaGlassButton(prominent: false)
                        .tint(Palette.violet)
                }
            }
        }
        .frame(minHeight: showsBrand ? 72 : 44)
    }
}

#Preview("Header – Dark") {
    HeaderView(onSettings: {})
        .padding()
        .background(.black)
        .preferredColorScheme(.dark)
}

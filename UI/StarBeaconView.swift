import SwiftUI

/// Hero beacon: rounded star inside a liquid-glass ring.
/// Breath + spin intensify while `isActive` (jailbreak / stage run).
struct StarBeaconView: View {
    var isActive: Bool
    @State private var breath = false
    @State private var spin = false

    var body: some View {
        ZStack {
            Circle()
                .fill(
                    RadialGradient(
                        colors: [
                            Lum1naPalette.magenta.opacity(isActive ? 0.45 : 0.28),
                            Lum1naPalette.violet.opacity(0.18),
                            .clear
                        ],
                        center: .center,
                        startRadius: 10,
                        endRadius: 120
                    )
                )
                .frame(width: 240, height: 240)
                .blur(radius: 8)
                .scaleEffect(breath ? 1.06 : 0.94)

            Circle()
                .stroke(Lum1naPalette.ringGradient, lineWidth: 3)
                .frame(width: 150, height: 150)
                .blur(radius: 0.2)
                .opacity(0.95)
                .overlay(
                    Circle()
                        .stroke(Color.white.opacity(0.25), lineWidth: 1)
                        .frame(width: 150, height: 150)
                )
                .background(ringGlass)

            Image(systemName: "star.fill")
                .resizable()
                .scaledToFit()
                .frame(width: 72, height: 72)
                .foregroundStyle(
                    LinearGradient(
                        colors: [.white, Lum1naPalette.magenta, Lum1naPalette.ice],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .shadow(color: Lum1naPalette.magenta.opacity(0.9), radius: isActive ? 22 : 12)
                .shadow(color: Lum1naPalette.ice.opacity(0.6), radius: isActive ? 16 : 8)
                .rotationEffect(.degrees(spin ? 360 : 0))
                .scaleEffect(breath ? 1.05 : 0.97)
        }
        .onAppear { startIdleMotion() }
        .onChange(of: isActive) { active in
            if active {
                withAnimation(.linear(duration: 2.4).repeatForever(autoreverses: false)) {
                    spin = true
                }
                withAnimation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true)) {
                    breath = true
                }
            } else {
                startIdleMotion()
            }
        }
    }

    private func startIdleMotion() {
        spin = false
        withAnimation(.easeInOut(duration: 3.4).repeatForever(autoreverses: true)) {
            breath = true
        }
    }

    @ViewBuilder
    private var ringGlass: some View {
        if #available(iOS 26.0, *) {
            Circle()
                .fill(.clear)
                .frame(width: 158, height: 158)
                .glassEffect(.regular.interactive(), in: .circle)
        } else {
            Circle()
                .fill(.ultraThinMaterial)
                .frame(width: 158, height: 158)
                .opacity(0.35)
        }
    }
}

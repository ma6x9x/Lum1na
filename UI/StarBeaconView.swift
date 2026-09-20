import SwiftUI

/// Hero beacon: rounded star inside a liquid-glass bubble with Siri27-style
/// rainbow ribbon + rubber-band drag. Breath/spin/wave intensify while active.
struct StarBeaconView: View {
    var isActive: Bool
    /// Wave intensity 0...1 (driven by ExploitManager.isRunning — not mic).
    var power: Double = 0.15

    @StateObject private var motion = LiquidBubbleMotionState()
    @State private var breath = false
    @State private var spin = false
    @State private var floatY: CGFloat = 0

    private let discDiameter: CGFloat = 158

    var body: some View {
        ZStack {
            // Soft magenta/violet bloom behind the glass.
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
                .offset(y: floatY)

            bubble
                .offset(x: motion.offset.width, y: motion.offset.height + floatY)
                .scaleEffect(x: motion.scaleX * (breath ? 1.02 : 0.98),
                             y: motion.scaleY * (breath ? 1.02 : 0.98))
                .gesture(dragGesture)
        }
        .frame(height: 260)
        .onAppear { startIdleMotion() }
        .onChange(of: isActive) { active in
            if active {
                withAnimation(.linear(duration: 2.4).repeatForever(autoreverses: false)) {
                    spin = true
                }
                withAnimation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true)) {
                    breath = true
                }
                withAnimation(.easeInOut(duration: 2.6).repeatForever(autoreverses: true)) {
                    floatY = -6
                }
            } else {
                floatY = 0
                startIdleMotion()
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(isActive ? "Lum1na beacon active" : "Lum1na beacon")
        .accessibilityAddTraits(.isImage)
    }

    private var bubble: some View {
        ZStack {
            LiquidGlassDisc(diameter: discDiameter)
                .overlay {
                    Circle()
                        .stroke(Lum1naPalette.ringGradient, lineWidth: 2.5)
                        .frame(width: discDiameter - 8, height: discDiameter - 8)
                        .blur(radius: 0.2)
                        .opacity(0.95)
                }

            // Rainbow ribbon clipped to the glass disc (Siri27 twin, power-driven).
            RainbowWaveRibbonView(power: clampedPower)
                .frame(width: discDiameter - 12, height: 72)
                .clipShape(Capsule(style: .continuous))
                .opacity(0.55 + clampedPower * 0.4)
                .allowsHitTesting(false)

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
    }

    private var clampedPower: Double {
        min(1.0, max(0.0, power))
    }

    private var dragGesture: some Gesture {
        DragGesture(minimumDistance: 2)
            .onChanged { value in
                if !motion.isDragging {
                    motion.beginDrag()
                }
                motion.updateDrag(
                    translation: value.translation,
                    velocity: CGSize(
                        width: value.predictedEndTranslation.width - value.translation.width,
                        height: value.predictedEndTranslation.height - value.translation.height
                    )
                )
            }
            .onEnded { _ in
                motion.endDrag()
            }
    }

    private func startIdleMotion() {
        spin = false
        withAnimation(.easeInOut(duration: 3.4).repeatForever(autoreverses: true)) {
            breath = true
        }
        withAnimation(.easeInOut(duration: 4.2).repeatForever(autoreverses: true)) {
            floatY = isActive ? -6 : -2
        }
    }
}

#Preview {
    ZStack {
        Lum1naPalette.field.ignoresSafeArea()
        VStack(spacing: 24) {
            StarBeaconView(isActive: false, power: 0.15)
            StarBeaconView(isActive: true, power: 0.8)
        }
    }
}

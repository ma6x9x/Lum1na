import SwiftUI

/// Wide purple glass PATCH control: neon rim, inner sheen, four-point star.
struct ActionButtonsView: View {
    @Environment(LuminaRunModel.self) private var model
    @Environment(\.luminaMotion) private var motion

    var body: some View {
        Button(action: primaryAction) {
            HStack(spacing: 14) {
                LuminaStarShape()
                    .fill(.white)
                    .frame(width: 18, height: 22)
                    .shadow(color: .white.opacity(0.9), radius: 4)
                Text(primaryTitle)
                    .font(.system(size: 22, weight: .semibold))
                    .tracking(3)
                    .padding(.trailing, -3)
            }
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity)
            .frame(height: 62)
            .glassSurface(Capsule(), tint: Palette.violet, interactive: true)
            .overlay { buttonWash }
            .fresnelRim(Capsule(), intensity: 0.85, glowWidth: 8)
            .overlay { buttonRim }
            .shadow(color: Palette.violet.opacity(model.phase == .running ? 0.35 : 0.85), radius: 16)
            .shadow(color: Palette.magenta.opacity(0.45), radius: 6)
        }
        .buttonStyle(.plain)
        .disabled(model.phase == .running)
        .animation(Motion.adaptive(Motion.smooth, motion: motion), value: model.phase)
        .accessibilityLabel(primaryTitle)
    }

    private var buttonWash: some View {
        Capsule()
            .fill(
                LinearGradient(
                    colors: [
                        Color(red: 0.55, green: 0.22, blue: 0.95).opacity(0.38),
                        Color(red: 0.28, green: 0.08, blue: 0.55).opacity(0.42)
                    ],
                    startPoint: .top,
                    endPoint: .bottom
                )
            )
            .allowsHitTesting(false)
    }

    private var buttonRim: some View {
        Capsule()
            .strokeBorder(
                LinearGradient(
                    colors: [
                        Color(red: 0.85, green: 0.65, blue: 1.0),
                        Palette.violet.opacity(0.9),
                        Color(red: 0.55, green: 0.25, blue: 0.95)
                    ],
                    startPoint: .top,
                    endPoint: .bottom
                ),
                lineWidth: 1.2
            )
            .allowsHitTesting(false)
    }

    private func primaryAction() {
        switch model.phase {
        case .idle, .cancelled:
            Task { await ExploitManager.shared.executeStage("Full Chain") }
        case .running:
            break
        case .success:
            ExploitManager.shared.reset()
            model.applyLive(running: false, stage: nil, progress: 0, proven: false)
        }
    }

    private var primaryTitle: String {
        switch model.phase {
        case .idle, .cancelled: "PATCH"
        case .running: "RUNNING"
        case .success: "RESET"
        }
    }
}

#Preview("Buttons – Dark") {
    ActionButtonsView()
        .environment(LuminaRunModel())
        .environment(\.luminaMotion, MotionLevel.full)
        .padding()
        .background(.black)
        .preferredColorScheme(.dark)
}

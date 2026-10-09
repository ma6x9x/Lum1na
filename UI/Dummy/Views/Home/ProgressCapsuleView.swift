import SwiftUI

/// The "STEP n OF 4" progress capsule that morphs into the "Illuminated" success
/// state using `GlassEffectContainer` + `glassEffectID` matched-geometry morphing.
struct ProgressCapsuleView: View {
    @Environment(LuminaRunModel.self) private var model
    @Environment(\.luminaMotion) private var motion

    @Namespace private var glassNamespace

    private var percent: Int { Int((model.progress * 100).rounded()) }

    var body: some View {
        LuminaGlassCluster(spacing: 20) {
            if model.isFinished {
                successContent
            } else {
                progressContent
            }
        }
        .animation(Motion.adaptive(Motion.smooth, motion: motion), value: model.isFinished)
    }

    private var progressContent: some View {
        HStack(spacing: 12) {
            Text(model.stepText)
                .font(.caption.weight(.semibold))
                .tracking(0.8)
                .foregroundStyle(.secondary)
            ProgressTrackView(progress: model.progress, motion: motion)
            Text("\(percent)%")
                .font(.caption.weight(.semibold).monospacedDigit())
                .contentTransition(.numericText(value: Double(percent)))
                .foregroundStyle(.primary)
                .frame(width: 42, alignment: .trailing)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity)
        .glassSurface(Capsule())
        .luminaGlassID("progressCapsule", in: glassNamespace)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(model.stepText)
        .accessibilityValue("\(percent) percent")
    }

    private var successContent: some View {
        HStack(spacing: 8) {
            Image(systemName: "sparkles")
            Text("Illuminated")
                .font(.subheadline.weight(.semibold))
        }
        .foregroundStyle(.white)
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity)
        .glassSurface(Capsule(), tint: Palette.violet.opacity(0.55))
        .luminaGlassID("progressCapsule", in: glassNamespace)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Illuminated")
    }
}

#Preview("Progress capsule – Dark") {
    ProgressCapsuleView()
        .environment(LuminaRunModel())
        .environment(\.luminaMotion, MotionLevel.full)
        .padding()
        .background(.black)
        .preferredColorScheme(.dark)
}

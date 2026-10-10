import SwiftUI

/// The hero band: the microchip with the star die at the centre and the four
/// stage pads in the corners, positioned with `HeroLayout` so they sit exactly
/// on the board's buses. Drives star breathing/flare and the run haptics.
struct CircuitHeroView: View {
    @Environment(LuminaRunModel.self) private var model
    @Environment(\.luminaMotion) private var motion

    @Namespace private var glassNamespace

    var body: some View {
        GeometryReader { proxy in
            let layout = HeroLayout(in: CGRect(origin: .zero, size: proxy.size))
            let moving = motion.allowsContinuousMotion
            TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: !moving)) { timeline in
                let now = moving ? timeline.date : .distantPast
                content(layout: layout, now: now)
                    .frame(width: proxy.size.width, height: proxy.size.height)
            }
        }
        .sensoryFeedback(.success, trigger: model.isFinished) { _, now in now }
        .sensoryFeedback(.impact(weight: .light, intensity: 0.7), trigger: model.stageTickCount)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Lum1na circuit, \(model.statusText)")
    }

    private func content(layout: HeroLayout, now: Date) -> some View {
        let t = now.timeIntervalSinceReferenceDate
        let amp = motion.amplitude
        let snapshot = model.boardSnapshot
        let running = model.isRunning ? 0.06 * sin(t * 3.3) * amp : 0
        return ZStack {
            LuminaGlassCluster(spacing: 8) {
                ZStack {
                    ForEach(RunStage.allCases) { stage in
                        StageNodeView(
                            stage: stage,
                            status: model.status(for: stage),
                            size: layout.nodeSize,
                            labelBelow: stage.corner.y > 0,
                            pulse: model.status(for: stage) == .active ? 0.5 + 0.5 * sin(t * 5.5) * max(amp, 0.0) : 0
                        )
                        .luminaGlassID(String(stage.id), in: glassNamespace)
                        .position(layout.nodeCenters[stage.rawValue])
                        .animation(Motion.adaptive(Motion.lively, motion: motion), value: model.status(for: stage))
                    }
                }
                .frame(width: layout.bounds.width, height: layout.bounds.height)
            }
            MicrochipView(
                size: layout.chipSize,
                intensity: snapshot.starIntensity + running,
                flare: flare(at: now),
                breathe: 1 + 0.025 * sin(t * 1.55) * amp,
                chipMark: Self.chipSilk
            )
            .position(layout.center)
        }
    }

    /// Package silk. `hw.machine` decides the token, so an iPad8,* reads A12X.
    private static var chipSilk: String {
        let chip = DeviceUtils.deviceCategory
        guard chip != "Unknown" else { return "LUM1NA" }
        return "LUM1NA·\(chip)"
    }

    /// 0…1…0 over 1.4 s after success.
    private func flare(at now: Date) -> Double {
        guard let start = model.successDate else { return 0 }
        guard motion.allowsContinuousMotion else { return model.isFinished ? 0.25 : 0 }
        let age = now.timeIntervalSince(start)
        guard age >= 0 && age < 1.4 else { return 0 }
        return sin(age / 1.4 * .pi)
    }
}

#Preview("Hero – Dark") {
    CircuitHeroView()
        .environment(LuminaRunModel())
        .environment(\.luminaMotion, MotionLevel.full)
        .frame(height: 340)
        .background(Color(red: 0.02, green: 0.024, blue: 0.06))
        .preferredColorScheme(.dark)
}

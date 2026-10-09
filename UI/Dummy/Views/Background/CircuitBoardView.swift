import SwiftUI

/// Full-screen procedural circuit board. Geometry is generated once per size
/// and aligned to the hero (whose global frame is passed in), so buses land on
/// the SwiftUI chip and stage nodes. A static `Canvas` draws the unlit board;
/// `BoardEnergyLayer` animates on top. Under Reduce Motion / Motion Off the
/// lit state crossfades between run steps instead of animating.
struct CircuitBoardView: View {
    /// Hero frame in global coordinates; `nil` centres a default hero (sheets).
    var heroFrame: CGRect?
    var snapshot = BoardSnapshot()
    /// `false` draws only the static board (sheet backdrops).
    var animated = true

    @Environment(\.colorScheme) private var scheme
    @Environment(\.luminaMotion) private var motion

    @State private var boardFrame: CGRect = .zero
    @State private var layout: BoardLayout?
    @State private var generation = 0

    var body: some View {
        ZStack {
            Palette.boardBase(for: scheme)
            if let layout {
                BoardStaticLayer(layout: layout, generation: generation, isDark: scheme == .dark)
                    .equatable()
                if animated {
                    energy(layout)
                }
            }
        }
        .animation(motion.allowsContinuousMotion ? nil : .easeInOut(duration: 0.35), value: litKey)
        .ignoresSafeArea()
        .onGeometryChange(for: CGRect.self) { proxy in
            proxy.frame(in: .global)
        } action: { frame in
            boardFrame = frame
        }
        .onChange(of: layoutKey, initial: true) {
            rebuild()
        }
        .accessibilityHidden(true)
    }

    @ViewBuilder
    private func energy(_ layout: BoardLayout) -> some View {
        let layer = BoardEnergyLayer(layout: layout, snapshot: snapshot, motion: motion, isDark: scheme == .dark)
        if motion.allowsContinuousMotion {
            layer
        } else {
            // Static lit board: crossfade whenever the lit state changes.
            layer
                .id(litKey)
                .transition(.opacity)
        }
    }

    /// Changes only when the static lit picture should change.
    private var litKey: [Int] {
        [snapshot.activeStage, snapshot.completedStages, snapshot.litMask, snapshot.phase == .success ? 1 : 0]
    }

    /// Rounded geometry inputs; the board regenerates only when these change.
    private var layoutKey: [Int] {
        let hero = localHeroRect
        return [boardFrame.width, boardFrame.height, hero.minX, hero.minY, hero.width, hero.height].map { Int($0.rounded()) }
    }

    private var localHeroRect: CGRect {
        guard let heroFrame, heroFrame.width > 0 else {
            let height = boardFrame.height * 0.42
            return CGRect(x: 0, y: boardFrame.height * 0.08, width: boardFrame.width, height: height)
        }
        return heroFrame.offsetBy(dx: -boardFrame.minX, dy: -boardFrame.minY)
    }

    private func rebuild() {
        guard boardFrame.width > 1, boardFrame.height > 1 else { return }
        layout = BoardLayout(size: boardFrame.size, hero: HeroLayout(in: localHeroRect))
        generation += 1
    }
}

#Preview("Board – Dark") {
    CircuitBoardView(snapshot: BoardSnapshot(phase: .running, activeStage: 1, completedStages: 1, progress: 0.4))
        .environment(\.luminaMotion, MotionLevel.full)
        .preferredColorScheme(.dark)
}

#Preview("Board – Light") {
    CircuitBoardView()
        .environment(\.luminaMotion, MotionLevel.full)
        .preferredColorScheme(.light)
}

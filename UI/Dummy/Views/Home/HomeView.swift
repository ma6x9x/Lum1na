import SwiftUI

/// The main screen: a full-screen animated circuit board with the star-on-chip
/// hero (~top half), then progress, the CRT console and the actions. The hero
/// reports its global frame so the board's buses line up with the chip/nodes.
struct HomeView: View {
    @Environment(LuminaRunModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @Environment(\.luminaMotion) private var motion

    @State private var showSettings = false
    @State private var consoleExpanded = false
    @State private var heroFrame: CGRect = .zero

    var body: some View {
        ZStack {
            CircuitBoardView(heroFrame: heroFrame, snapshot: model.boardSnapshot)
            VStack(spacing: 8) {
                HeaderView(
                    showsDone: showSettings,
                    onSettings: openSettings,
                    onDone: closeSettings
                )
                .padding(.horizontal, 18)

                CircuitHeroView()
                    .frame(maxHeight: heroCap)
                    .onGeometryChange(for: CGRect.self) { proxy in
                        proxy.frame(in: .global)
                    } action: { frame in
                        heroFrame = frame
                    }

                if showSettings {
                    SettingsSheetView()
                        .frame(maxWidth: 560)
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
                        .transition(.opacity.combined(with: .move(edge: .bottom)))
                } else {
                    VStack(spacing: 8) {
                        ConsoleCardView(expanded: consoleExpanded, onExpand: toggleConsole)
                            .layoutPriority(consoleExpanded ? 1 : 0)
                        if !consoleExpanded {
                            Spacer(minLength: 4)
                        }
                        ActionButtonsView()
                        DeviceProgressBar()
                            .padding(.bottom, 6)
                    }
                    .padding(.horizontal, 18)
                    .frame(maxHeight: .infinity)
                    .transition(.opacity)
                }
            }
            .padding(.top, 4)
        }
        .animation(Motion.adaptive(Motion.smooth, motion: motion), value: showSettings)
        .animation(Motion.adaptive(Motion.smooth, motion: motion), value: consoleExpanded)
    }

    /// Hero stays put while settings is open so the board traces don't jump.
    /// Expanding the log gives the console the space under a shorter hero.
    private var heroCap: CGFloat {
        if consoleExpanded { return 188 }
        return 300
    }

    private func openSettings() {
        consoleExpanded = false
        showSettings = true
    }

    private func closeSettings() {
        showSettings = false
    }

    private func toggleConsole() {
        consoleExpanded.toggle()
    }
}

#Preview("Home – Dark") {
    HomeView()
        .environment(LuminaRunModel())
        .environment(AppSettings())
        .environment(\.luminaMotion, MotionLevel.full)
        .preferredColorScheme(.dark)
}

#Preview("Home – Light") {
    HomeView()
        .environment(LuminaRunModel())
        .environment(AppSettings())
        .environment(\.luminaMotion, MotionLevel.full)
        .preferredColorScheme(.light)
}

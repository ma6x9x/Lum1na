import SwiftUI

/// Panels that can take over the home board. All of them render inside the
/// same centered `BoardPanelView` card; only the circuit background (and the
/// header) stay visible behind them.
enum HomePanel {
    case settings
    case catalog
    case lab
}

/// The main screen: a full-screen animated circuit board with the star-on-chip
/// hero (~top half), then progress, the CRT console and the actions. The hero
/// reports its global frame so the board's buses line up with the chip/nodes.
/// Opening a panel hides everything except the board background and swaps in
/// one centered panel card.
struct HomeView: View {
    @Environment(LuminaRunModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @Environment(\.luminaMotion) private var motion

    @State private var activePanel: HomePanel?
    @State private var consoleExpanded = false
    @State private var heroFrame: CGRect = .zero

    var body: some View {
        ZStack {
            CircuitBoardView(heroFrame: heroFrame, snapshot: model.boardSnapshot)
            VStack(spacing: 8) {
                HeaderView(
                    showsDone: activePanel != nil,
                    onSettings: openPanel(.settings),
                    onDone: closePanel
                )
                .padding(.horizontal, 18)

                if let panel = activePanel {
                    panelView(panel)
                        .frame(maxWidth: 560)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .transition(.opacity.combined(with: .scale(scale: 0.96)))
                } else {
                    CircuitHeroView()
                        .frame(maxHeight: heroCap)
                        .onGeometryChange(for: CGRect.self) { proxy in
                            proxy.frame(in: .global)
                        } action: { frame in
                            heroFrame = frame
                        }

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
        .animation(Motion.adaptive(Motion.smooth, motion: motion), value: activePanel)
        .animation(Motion.adaptive(Motion.smooth, motion: motion), value: consoleExpanded)
    }

    @ViewBuilder
    private func panelView(_ panel: HomePanel) -> some View {
        switch panel {
        case .settings:
            BoardPanelView(title: "Settings") {
                SettingsPanelView(onOpen: { openPanel($0)() })
            }
        case .catalog:
            BoardPanelView(title: "All Exploits") {
                CatalogPanelView(viewModel: ExploitManager.shared, onClose: closePanel)
            }
        case .lab:
            BoardPanelView(title: "Lab") {
                LabPanelView(viewModel: ExploitManager.shared, onClose: closePanel)
            }
        }
    }

    /// Hero stays put while no panel is open so the board traces don't jump.
    /// Expanding the log gives the console the space under a shorter hero.
    private var heroCap: CGFloat {
        if consoleExpanded { return 188 }
        return 300
    }

    private func openPanel(_ panel: HomePanel) -> () -> Void {
        {
            consoleExpanded = false
            activePanel = panel
        }
    }

    private func closePanel() {
        activePanel = nil
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

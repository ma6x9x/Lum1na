import SwiftUI

/// Panels that take over the home board. All of them sit on the live circuit
/// background; the hero, compact console and jailbreak hide. The LUM1NA
/// header stays (gear becomes Done).
enum HomePanel {
    case settings
    case catalog
    case lab
    case console
}

/// The main screen: a full-screen animated circuit board with the star-on-chip
/// hero (~top half), then the CRT console and the actions. The hero reports
/// its global frame so the board's buses line up with the chip/nodes.
struct HomeView: View {
    @Environment(LuminaRunModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @Environment(\.luminaMotion) private var motion

    @State private var activePanel: HomePanel?
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
                        .frame(maxWidth: panel == .console ? .infinity : 560)
                        .padding(.horizontal, 18)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .transition(.opacity.combined(with: .scale(scale: 0.96)))
                } else {
                    CircuitHeroView()
                        .frame(maxHeight: 300)
                        .onGeometryChange(for: CGRect.self) { proxy in
                            proxy.frame(in: .global)
                        } action: { frame in
                            // Ignore teardown frames so the board does not
                            // jump while a panel covers the hero.
                            guard frame.width > 8, frame.height > 8 else { return }
                            heroFrame = frame
                        }

                    VStack(spacing: 8) {
                        ConsoleCardView(onExpand: openPanel(.console))
                        Spacer(minLength: 4)
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
        case .console:
            ConsolePanelView(onClose: closePanel)
        }
    }

    private func openPanel(_ panel: HomePanel) -> () -> Void {
        {
            activePanel = panel
        }
    }

    private func closePanel() {
        activePanel = nil
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

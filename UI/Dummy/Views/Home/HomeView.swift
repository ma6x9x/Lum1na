import SwiftUI

/// The main screen: a full-screen animated circuit board with the star-on-chip
/// hero (~top half), then progress, the CRT console and the actions. The hero
/// reports its global frame so the board's buses line up with the chip/nodes.
struct HomeView: View {
    @Environment(LuminaRunModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @Environment(\.luminaMotion) private var motion

    @State private var showSettings = false
    @State private var showConsole = false
    @State private var heroFrame: CGRect = .zero

    var body: some View {
        ZStack {
            CircuitBoardView(heroFrame: heroFrame, snapshot: model.boardSnapshot)
            VStack(spacing: 8) {
                HeaderView(onSettings: openSettings)
                    .padding(.horizontal, 18)
                CircuitHeroView()
                    .frame(maxHeight: 300)
                    .onGeometryChange(for: CGRect.self) { proxy in
                        proxy.frame(in: .global)
                    } action: { frame in
                        heroFrame = frame
                    }
                ConsoleCardView(onExpand: openConsole)
                    .padding(.horizontal, 18)
                Spacer(minLength: 4)
                ActionButtonsView()
                    .padding(.horizontal, 22)
                DeviceProgressBar()
                    .padding(.horizontal, 22)
                    .padding(.bottom, 6)
            }
            .padding(.top, 4)
        }
        .sheet(isPresented: $showSettings) {
            SettingsSheetView()
                .environment(settings)
                .environment(model)
                .environment(\.luminaMotion, motion)
        }
        .sheet(isPresented: $showConsole) {
            ConsoleSheetView()
                .environment(model)
                .environment(settings)
                .environment(\.luminaMotion, motion)
        }
    }

    private func openSettings() { showSettings = true }
    private func openConsole() { showConsole = true }
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

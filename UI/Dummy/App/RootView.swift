import SwiftUI

/// Hosts shared app state and applies the user's appearance / motion choices
/// to the whole UI, including presented sheets.
struct RootView: View {
    @State private var settings = AppSettings()
    @State private var model = LuminaRunModel()
    @ObservedObject private var exploits = ExploitManager.shared
    @ObservedObject private var bootstrap = Lum1naBootstrap.shared

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HomeView()
            .environment(settings)
            .environment(model)
            .environment(\.luminaMotion, effectiveMotion)
            .preferredColorScheme(settings.appearance.preferredColorScheme)
            .tint(Palette.violet)
            .onAppear {
                // Post-respring truth: a jbroot dpkg either exists or it
                // does not. Detection only — never a claim of success.
                bootstrap.refreshInstalledState()
                syncLive()
            }
            .onChange(of: exploits.isRunning) { syncLive() }
            .onChange(of: exploits.fullChainActive) { syncLive() }
            .onChange(of: exploits.selectedStage) { syncLive() }
            .onChange(of: exploits.progress) { syncLive() }
            .onChange(of: bootstrap.bootstrapInstalled) { syncLive() }
            .onChange(of: bootstrap.pkgmanInstalled) { syncLive() }
    }

    private func syncLive() {
        model.applyLive(
            running: exploits.isRunning || exploits.fullChainActive,
            stage: exploits.selectedStage,
            progress: exploits.progress,
            proven: Lum1naBoard.shared().hasKread || bootstrap.bootstrapInstalled
        )
    }

    private var effectiveMotion: MotionLevel {
        if reduceMotion { return .off }
        return settings.motion.level
    }
}

#Preview("Root – Dark") {
    RootView()
        .preferredColorScheme(.dark)
}

#Preview("Root – Light") {
    RootView()
        .preferredColorScheme(.light)
}

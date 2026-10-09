import SwiftUI

/// Settings sheet modelled on the glass card mock. Appearance, Motion and the
/// console options actually drive the UI; Device / System are fixed cosmetic values.
struct SettingsSheetView: View {
    @Environment(AppSettings.self) private var settings
    @Environment(\.dismiss) private var dismiss
    @State private var showExploits = false
    @State private var showLab = false

    var body: some View {
        @Bindable var settings = settings
        NavigationStack {
            ZStack {
                CircuitBoardView(animated: false)
                ScrollView {
                    VStack(spacing: 20) {
                        header
                        VStack(spacing: 12) {
                            SettingsRowView(title: "Device") {
                                Text(DeviceUtils.headerDeviceLine)
                                    .lineLimit(1)
                            }
                            SettingsRowView(title: "System") {
                                Text(DeviceUtils.osversion)
                            }
                            SettingsRowView(title: "Appearance") {
                                Picker("Appearance", selection: $settings.appearance) {
                                    ForEach(AppearanceMode.allCases) { Text($0.label).tag($0) }
                                }
                                .labelsHidden()
                            }
                            SettingsRowView(title: "Motion") {
                                Picker("Motion", selection: $settings.motion) {
                                    ForEach(MotionMode.allCases) { Text($0.label).tag($0) }
                                }
                                .labelsHidden()
                            }
                            SettingsRowView(title: "Console") {
                                Picker("Console", selection: $settings.console) {
                                    ForEach(ConsoleMode.allCases) { Text($0.label).tag($0) }
                                }
                                .labelsHidden()
                            }
                            SettingsRowView(title: "Console style") {
                                Picker("Console style", selection: $settings.consoleStyle) {
                                    ForEach(ConsoleStyle.allCases) { Text($0.label).tag($0) }
                                }
                                .labelsHidden()
                            }
                            SettingsRowView(title: "Catalog") {
                                Button("All Exploits") { showExploits = true }
                            }
                            SettingsRowView(title: "Lab") {
                                Button("Device and logs") { showLab = true }
                            }
                        }
                        .padding(14)
                        .glassSurface(RoundedRectangle(cornerRadius: 28, style: .continuous))
                        Text("Jailbreak runs the live chain. It does not report success until kreadbuf is proven.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 6)
                    }
                    .padding(20)
                }
                .scrollIndicators(.hidden)
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .toolbarTitleDisplayMode(.inline)
            .sheet(isPresented: $showExploits) {
                AllExploitsSheet(viewModel: ExploitManager.shared)
            }
            .sheet(isPresented: $showLab) {
                SettingsSheet(viewModel: ExploitManager.shared)
            }
        }
    }

    private var header: some View {
        VStack(spacing: 10) {
            WordmarkView(size: 30)
            Image(.luminaLogo)
                .resizable()
                .scaledToFit()
                .frame(width: 52, height: 52)
                .accessibilityHidden(true)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 8)
    }
}

#Preview("Settings – Dark") {
    SettingsSheetView()
        .environment(AppSettings())
        .environment(\.luminaMotion, MotionLevel.full)
        .preferredColorScheme(.dark)
}

#Preview("Settings – Light") {
    SettingsSheetView()
        .environment(AppSettings())
        .environment(\.luminaMotion, MotionLevel.full)
        .preferredColorScheme(.light)
}

import SwiftUI

/// Settings card drawn on the live home board. Appearance, Motion and the
/// console options drive the UI. Device / System come from the running hardware.
struct SettingsSheetView: View {
    @Environment(AppSettings.self) private var settings
    @State private var showExploits = false
    @State private var showLab = false

    var body: some View {
        @Bindable var settings = settings
        GeometryReader { proxy in
            ScrollView {
                panel(settings)
                    .frame(maxWidth: .infinity, minHeight: proxy.size.height, alignment: .center)
            }
            .scrollIndicators(.hidden)
        }
        .sheet(isPresented: $showExploits) {
            AllExploitsSheet(viewModel: ExploitManager.shared)
        }
        .sheet(isPresented: $showLab) {
            SettingsSheet(viewModel: ExploitManager.shared)
        }
    }

    private func panel(_ settings: AppSettings) -> some View {
        @Bindable var settings = settings
        return VStack(spacing: 14) {
                VStack(spacing: 12) {
                    SettingsRowView(title: "Device") {
                        Text(DeviceUtils.headerDeviceLine)
                            .lineLimit(1)
                            .minimumScaleFactor(0.7)
                    }
                    SettingsRowView(title: "System") {
                        Text(DeviceUtils.osversion)
                    }
                    SettingsRowView(title: "Appearance") {
                        Picker("Appearance", selection: $settings.appearance) {
                            ForEach(AppearanceMode.allCases) { Text($0.label).tag($0) }
                        }
                        .labelsHidden()
                        .pickerStyle(.menu)
                    }
                    SettingsRowView(title: "Motion") {
                        Picker("Motion", selection: $settings.motion) {
                            ForEach(MotionMode.allCases) { Text($0.label).tag($0) }
                        }
                        .labelsHidden()
                        .pickerStyle(.menu)
                    }
                    SettingsRowView(title: "Console") {
                        Picker("Console", selection: $settings.console) {
                            ForEach(ConsoleMode.allCases) { Text($0.label).tag($0) }
                        }
                        .labelsHidden()
                        .pickerStyle(.menu)
                    }
                    SettingsRowView(title: "Console style") {
                        Picker("Console style", selection: $settings.consoleStyle) {
                            ForEach(ConsoleStyle.allCases) { Text($0.label).tag($0) }
                        }
                        .labelsHidden()
                        .pickerStyle(.menu)
                    }
                    Button {
                        showExploits = true
                    } label: {
                        SettingsRowView(title: "Catalog") {
                            Text("All Exploits")
                        }
                    }
                    .buttonStyle(.plain)
                    .frame(maxWidth: .infinity)
                    Button {
                        showLab = true
                    } label: {
                        SettingsRowView(title: "Lab") {
                            Text("Device and logs")
                        }
                    }
                    .buttonStyle(.plain)
                    .frame(maxWidth: .infinity)
                }
                .padding(14)
                .glassSurface(RoundedRectangle(cornerRadius: 28, style: .continuous))

                Text("Jailbreak runs the live chain. It does not report success until kreadbuf is proven.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                    .padding(.horizontal, 8)
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity)
    }
}

#Preview("Settings – Dark") {
    ZStack {
        Palette.boardBase(for: .dark).ignoresSafeArea()
        SettingsSheetView()
    }
    .environment(AppSettings())
    .environment(\.luminaMotion, MotionLevel.full)
    .preferredColorScheme(.dark)
}

#Preview("Settings – Light") {
    ZStack {
        Palette.boardBase(for: .light).ignoresSafeArea()
        SettingsSheetView()
    }
    .environment(AppSettings())
    .environment(\.luminaMotion, MotionLevel.full)
    .preferredColorScheme(.light)
}

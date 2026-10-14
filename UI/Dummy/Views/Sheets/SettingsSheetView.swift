import SwiftUI

/// Settings panel content, hosted by `BoardPanelView` on the live home board.
/// Appearance, Motion and the console options drive the UI. Device / System
/// come from the running hardware. Catalog and Lab open as sibling panels.
struct SettingsPanelView: View {
    @Environment(AppSettings.self) private var settings
    var onOpen: (HomePanel) -> Void

    var body: some View {
        @Bindable var settings = settings
        VStack(spacing: 14) {
            VStack(spacing: 12) {
                SettingsRowView(title: "Device") {
                    Text(DeviceUtils.headerDeviceLine)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                }
                SettingsRowView(title: "System") {
                    Text(DeviceUtils.osversion)
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
                    onOpen(.catalog)
                } label: {
                    SettingsRowView(title: "Catalog") {
                        Text("All Exploits")
                    }
                }
                .buttonStyle(.plain)
                .frame(maxWidth: .infinity)
                Button {
                    onOpen(.lab)
                } label: {
                    SettingsRowView(title: "Lab") {
                        Text("Device and logs")
                    }
                }
                .buttonStyle(.plain)
                .frame(maxWidth: .infinity)
            }

            Text("Jailbreak runs the live chain. It does not report success until kreadbuf is proven.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
                .padding(.horizontal, 8)
        }
        .padding(.horizontal, 4)
    }
}

#Preview("Settings panel") {
    BoardPanelView(title: "Settings") {
        SettingsPanelView(onOpen: { _ in })
            .environment(AppSettings())
    }
    .frame(maxWidth: 560)
    .padding(18)
    .background(Color(red: 0.02, green: 0.024, blue: 0.06))
    .preferredColorScheme(.dark)
}

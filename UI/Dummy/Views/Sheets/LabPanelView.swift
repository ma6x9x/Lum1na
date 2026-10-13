import SwiftUI

/// Lab / debug panel: device info, exploit state, copy-log actions. Same
/// centered card pattern as the settings and catalog panels.
struct LabPanelView: View {
    @ObservedObject var viewModel: ExploitManager
    var onClose: () -> Void
    @State private var showHour = false

    private func hex(_ value: UInt64) -> String {
        value != 0 ? "0x" + String(value, radix: 16, uppercase: true) : "Not obtained"
    }

    private func boardLeakLabel() -> String {
        let leaks = Lum1naBoard.shared().leaks ?? []
        var hits = 0
        for e in leaks {
            let n = (e["hits"] as? Int) ?? (e["hits"] as? NSNumber)?.intValue ?? 1
            hits += max(n, 1)
        }
        return "\(leaks.count) unique / \(hits) hits"
    }

    var body: some View {
        VStack(spacing: 14) {
            VStack(spacing: 12) {
                sectionHeader("DEVICE INFO")
                VStack(spacing: 10) {
                    SettingsRowView(title: "Product") { Text(DeviceUtils.friendlyProduct) }
                    SettingsRowView(title: "Machine") { Text(DeviceUtils.currentDeviceIdentifier) }
                    SettingsRowView(title: "iOS") { Text(DeviceUtils.marketingVersion) }
                    SettingsRowView(title: "Build") { Text(DeviceUtils.osversion) }
                    SettingsRowView(title: "Chip") { Text(DeviceUtils.currentChip) }
                    SettingsRowView(title: "Offset table") { Text(labOffsetTag()) }
                    SettingsRowView(title: "Supported") {
                        Text(DeviceUtils.isSupported ? "Yes" : "No")
                    }
                }

                sectionHeader("EXPLOIT STATE")
                VStack(spacing: 10) {
                    SettingsRowView(title: "Kernel Slide") {
                        Text(hex(viewModel.currentKernelSlide))
                            .lineLimit(1)
                            .minimumScaleFactor(0.6)
                    }
                    SettingsRowView(title: "Kernel Base") {
                        Text(hex(viewModel.currentKernelBase))
                            .lineLimit(1)
                            .minimumScaleFactor(0.6)
                    }
                    SettingsRowView(title: "Last Result") {
                        Text(viewModel.lastResult.isSuccess ? "Success" : "Idle/Failure")
                    }
                    if !viewModel.lastRecoverySummary.isEmpty {
                        SettingsRowView(title: "Last Crash") {
                            Text(viewModel.lastRecoverySummary)
                                .lineLimit(2)
                                .minimumScaleFactor(0.6)
                        }
                    }
                }

                sectionHeader("LAB / DEBUG")
                VStack(spacing: 10) {
                    SettingsRowView(title: "Last TAP") {
                        Text(PersistentLogStore.shared.lastTapId() ?? "none")
                    }
                    SettingsRowView(title: "SKU") {
                        Text(LabDeviceProfile.skuName() as String? ?? "?")
                    }
                    actionRow("Run Ident", icon: "person.crop.rectangle") {
                        if let ident = ExploitManager.catalog.first(where: { $0.id == "ident" }) {
                            onClose()
                            Task { await viewModel.executeExploit(ident) }
                        }
                    }
                    actionRow("Copy Ident Block", icon: "doc.on.doc") {
                        UIPasteboard.general.string = LabDeviceProfile.identBlock()
                    }
                    actionRow("Copy TAP Log (p011)", icon: "hand.tap") {
                        UIPasteboard.general.string =
                            PersistentLogStore.shared.readTapLog() ?? ""
                    }
                    actionRow("Copy Console Buffer", icon: "terminal") {
                        UIPasteboard.general.string = viewModel.exportFullDebugLog()
                    }
                    actionRow("Copy Kernel Board JSON", icon: "cpu") {
                        UIPasteboard.general.string = Lum1naBoard.shared().jsonDump()
                    }
                    SettingsRowView(title: "Board kread") {
                        Text(Lum1naBoard.shared().hasKread ? "yes" : "no")
                    }
                    SettingsRowView(title: "Board leaks") { Text(boardLeakLabel()) }
                }

                sectionHeader("RECOVERY LOG")
                VStack(spacing: 10) {
                    actionRow("Copy Recovery Packet", icon: "clock.arrow.circlepath") {
                        let packet = viewModel.lastRecoveryTranscript.isEmpty
                            ? PersistentLogStore.shared.captureRecoveryPacket(
                                boardJSON: Lum1naBoard.shared().jsonDump(),
                                sku: LabDeviceProfile.skuName() as String? ?? "?",
                                unclean: false,
                                previousSession: true)
                            : viewModel.lastRecoveryTranscript
                        UIPasteboard.general.string = packet
                    }
                    actionRow("Copy Full Disk Log", icon: "doc.text") {
                        UIPasteboard.general.string =
                            PersistentLogStore.shared.readAll() ?? ""
                    }
                    actionRow("Logs from the last hour", icon: "clock") {
                        showHour = true
                    }
                    actionRow("Clear Disk Logs", icon: "trash", tint: .red) {
                        PersistentLogStore.shared.clear()
                    }
                }

                Text("Recovery packet is the previous session (board + last console session + TAP markers), captured at launch. Console Copy is this session only. Full Disk is everything.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                    .padding(.horizontal, 8)
            }
        }
        .padding(.horizontal, 4)
        .sheet(isPresented: $showHour) {
            HourLogGallery()
        }
    }

    private func sectionHeader(_ text: String) -> some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .tracking(1.2)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 6)
    }

    private func actionRow(_ title: String,
                           icon: String,
                           tint: Color = .secondary,
                           action: @escaping () -> Void) -> some View {
        Button(action: action) {
            SettingsRowView(title: title) {
                Image(systemName: icon)
                    .foregroundStyle(tint)
            }
        }
        .buttonStyle(.plain)
        .frame(maxWidth: .infinity)
    }
}

#Preview("Lab panel") {
    BoardPanelView(title: "Lab") {
        LabPanelView(viewModel: ExploitManager.shared, onClose: {})
    }
    .frame(maxWidth: 560)
    .padding(18)
    .background(Color(red: 0.02, green: 0.024, blue: 0.06))
    .preferredColorScheme(.dark)
}

//
//  ToolsTabView.swift
//  Lum1na — only tools wired to existing façades (no placeholders).
//

import SwiftUI

struct ToolsTabView: View {
    @Environment(LuminaAppStore.self) private var store
    @State private var showSKU = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Tools")
                    .font(.largeTitle.bold())
                    .padding(.top, 8)

                toolSection("INSPECT") {
                    toolRow(
                        title: "Syslog export",
                        subtitle: "Copy the current console buffer",
                        systemImage: "doc.text",
                        tint: LuminaV2Theme.accent
                    ) {
                        store.copyToPasteboard(store.exportConsole())
                    }
                    toolRow(
                        title: "Hour logs",
                        subtitle: "Browse Documents logs from the last hour",
                        systemImage: "clock",
                        tint: LuminaV2Theme.cyan
                    ) {
                        store.showHourLogs = true
                    }
                    toolRow(
                        title: "Peek UI tree",
                        subtitle: "Dump the SwiftPeek twin into the console",
                        systemImage: "sparkle.magnifyingglass",
                        tint: LuminaV2Theme.ok
                    ) {
                        store.peekUITree()
                    }
                }

                toolSection("DEVICE") {
                    toolRow(
                        title: "SKU Inspector",
                        subtitle: "Machine, build, offset tag, board honesty",
                        systemImage: "cpu",
                        tint: LuminaV2Theme.cyan
                    ) {
                        showSKU = true
                    }
                    toolRow(
                        title: "Copy Ident block",
                        subtitle: "LabDeviceProfile.identBlock()",
                        systemImage: "person.crop.rectangle",
                        tint: LuminaV2Theme.amber
                    ) {
                        store.copyToPasteboard(LabDeviceProfile.identBlock() as String? ?? "")
                    }
                    toolRow(
                        title: "Copy board JSON",
                        subtitle: "Lum1naBoard.jsonDump()",
                        systemImage: "square.stack.3d.up",
                        tint: LuminaV2Theme.ok
                    ) {
                        store.copyToPasteboard(Lum1naBoard.shared().jsonDump())
                    }
                }

                toolSection("CAPTURE") {
                    toolRow(
                        title: "Export session",
                        subtitle: "Share last run summary + console",
                        systemImage: "square.and.arrow.up",
                        tint: LuminaV2Theme.ok
                    ) {
                        store.share(exportSessionText())
                    }
                    toolRow(
                        title: "Copy recovery packet",
                        subtitle: "Previous-session crash packet",
                        systemImage: "clock.arrow.circlepath",
                        tint: LuminaV2Theme.accent
                    ) {
                        let packet = store.lastRecoveryTranscript.isEmpty
                            ? PersistentLogStore.shared.captureRecoveryPacket(
                                boardJSON: Lum1naBoard.shared().jsonDump(),
                                sku: LabDeviceProfile.skuName() as String? ?? "?",
                                unclean: false,
                                previousSession: true)
                            : store.lastRecoveryTranscript
                        store.copyToPasteboard(packet)
                    }
                    toolRow(
                        title: "Embedded terminal",
                        subtitle: "Open the existing MainTerminalPane",
                        systemImage: "terminal",
                        tint: LuminaV2Theme.pending
                    ) {
                        store.showTerminal = true
                    }
                }
            }
            .padding(16)
            .padding(.bottom, LuminaV2Theme.chipClearance + LuminaV2Theme.tabBarHeight)
        }
        .sheet(isPresented: $showSKU) {
            NavigationStack {
                List {
                    Section("Device") {
                        LabeledContent("Product", value: DeviceUtils.friendlyProduct)
                        LabeledContent("Machine", value: store.machine)
                        LabeledContent("Board", value: store.boardConfig)
                        LabeledContent("iOS", value: store.iosVersion)
                        LabeledContent("Build", value: store.build)
                        LabeledContent("Chip", value: DeviceUtils.currentChip)
                        LabeledContent("Offset table", value: store.skuTag)
                        LabeledContent("SKU", value: LabDeviceProfile.skuName() as String? ?? "?")
                    }
                    Section("Honesty") {
                        LabeledContent("hasKread", value: store.hasKread ? "yes" : "no")
                        LabeledContent("conversion", value: store.conversionConfirmed ? "yes" : "no")
                        LabeledContent("magic", value: store.magicConfirmed ? "yes" : "no")
                        LabeledContent("Last TAP", value: store.lastTapId ?? "none")
                    }
                }
                .navigationTitle("SKU Inspector")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Close") { showSKU = false }
                    }
                }
            }
            .presentationDetents([.medium, .large])
        }
    }

    private func exportSessionText() -> String {
        var out = store.exportConsole()
        if let s = store.pinnedSummary {
            out += "\n\n=== Pinned summary ===\n"
            out += "\(s.catalogId) \(s.status.rawValue) \(String(format: "%.2fs", s.duration))\n"
            out += s.keyValues.joined(separator: ", ")
            out += "\n\n=== Run snapshot ===\n"
            out += s.snapshotText
        }
        return out
    }

    @ViewBuilder
    private func toolSection(_ title: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.leading, 4)
            VStack(spacing: 0) {
                content()
            }
            .luminaCard()
        }
    }

    private func toolRow(
        title: String,
        subtitle: String,
        systemImage: String,
        tint: Color,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: systemImage)
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.white)
                    .frame(width: 36, height: 36)
                    .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(tint.opacity(0.85)))
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.body.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)
            }
            .padding(16)
            .frame(minHeight: 44)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(title). \(subtitle)")
    }
}

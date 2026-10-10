//
//  ContentView.swift
//  Lum1na
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        RootView()
    }
}

struct AllExploitsSheet: View {
    @ObservedObject var viewModel: ExploitManager
    @Environment(\.dismiss) var dismiss

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("EXPLOIT CATALOG - TAP TO RUN INDIVIDUALLY")) {
                    ForEach(ExploitManager.catalog) { entry in
                        Button {
                            dismiss()
                            Task {
                                await viewModel.executeExploit(entry)
                            }
                        } label: {
                            HStack {
                                Image(systemName: entry.stage.icon)
                                    .foregroundColor(entry.stage.color)
                                    .frame(width: 24)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(entry.name)
                                        .font(.system(.subheadline, weight: .semibold))
                                        .foregroundColor(.primary)

                                    Text(entry.description)
                                        .font(.system(.caption, design: .rounded))
                                        .foregroundColor(.secondary)
                                }

                                Spacer()

                                if viewModel.isRunning &&
                                    viewModel.selectedStage == entry.stage {
                                    ProgressView()
                                        .scaleEffect(0.7)
                                } else {
                                    Image(systemName: "play.circle")
                                        .foregroundColor(entry.stage.color.opacity(0.7))
                                }
                            }
                        }
                        .disabled(viewModel.isRunning)
                    }
                }

                Section(footer: Text("Every invoke writes a durable TAP marker before running. After a crash, the recovery transcript shows exactly which entry was last attempted.")) {
                    EmptyView()
                }
            }
            .navigationTitle("All Exploits")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

struct SettingsSheet: View {
    @ObservedObject var viewModel: ExploitManager
    @Environment(\.dismiss) var dismiss
    @State private var showHour = false

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
        NavigationView {
            List {
                Section(header: Text("DEVICE INFO")) {
                    LabeledContent("Product", value: DeviceUtils.friendlyProduct)
                    LabeledContent("Machine", value: DeviceUtils.currentDeviceIdentifier)
                    LabeledContent("iOS", value: DeviceUtils.marketingVersion)
                    LabeledContent("Build", value: DeviceUtils.osversion)
                    LabeledContent("Chip", value: DeviceUtils.currentChip)
                    LabeledContent("Offset table", value: labOffsetTag())
                    LabeledContent("Supported",
                        value: DeviceUtils.isSupported ? "Yes" : "No")
                }

                Section(header: Text("EXPLOIT STATE")) {
                    LabeledContent("Kernel Slide",
                        value: viewModel.currentKernelSlide != 0
                            ? "0x" + String(viewModel.currentKernelSlide,
                                            radix: 16, uppercase: true)
                            : "Not obtained")
                    LabeledContent("Kernel Base",
                        value: viewModel.currentKernelBase != 0
                            ? "0x" + String(viewModel.currentKernelBase,
                                            radix: 16, uppercase: true)
                            : "Not obtained")
                    LabeledContent("Last Result",
                        value: viewModel.lastResult.isSuccess
                            ? "Success" : "Idle/Failure")
                    if !viewModel.lastRecoverySummary.isEmpty {
                        LabeledContent("Last Crash",
                            value: viewModel.lastRecoverySummary)
                    }
                }

                Section(header: Text("LAB / DEBUG")) {
                    LabeledContent("Last TAP",
                        value: PersistentLogStore.shared.lastTapId() ?? "none")
                    LabeledContent("SKU", value: LabDeviceProfile.skuName() as String? ?? "?")
                    Button {
                        if let ident = ExploitManager.catalog.first(where: { $0.id == "ident" }) {
                            dismiss()
                            Task { await viewModel.executeExploit(ident) }
                        }
                    } label: {
                        Label("Run Ident", systemImage: "person.crop.rectangle")
                    }
                    Button {
                        UIPasteboard.general.string = LabDeviceProfile.identBlock()
                    } label: {
                        Label("Copy Ident Block", systemImage: "doc.on.doc")
                    }
                    Button {
                        UIPasteboard.general.string =
                            PersistentLogStore.shared.readTapLog() ?? ""
                    } label: {
                        Label("Copy TAP Log (p011)", systemImage: "hand.tap")
                    }
                    Button {
                        UIPasteboard.general.string = viewModel.exportFullDebugLog()
                    } label: {
                        Label("Copy Console Buffer", systemImage: "terminal")
                    }
                    Button {
                        UIPasteboard.general.string = Lum1naBoard.shared().jsonDump()
                    } label: {
                        Label("Copy Kernel Board JSON", systemImage: "cpu")
                    }
                    LabeledContent("Board kread", value: Lum1naBoard.shared().hasKread ? "yes" : "no")
                    LabeledContent("Board leaks", value: boardLeakLabel())
                }

                Section(header: Text("RECOVERY LOG"),
                        footer: Text("Recovery packet is the previous session (board + last console session + TAP markers), captured at launch. Console Copy is this session only. Full Disk is everything.")) {
                    Button {
                        let packet = viewModel.lastRecoveryTranscript.isEmpty
                            ? PersistentLogStore.shared.captureRecoveryPacket(
                                boardJSON: Lum1naBoard.shared().jsonDump(),
                                sku: LabDeviceProfile.skuName() as String? ?? "?",
                                unclean: false,
                                previousSession: true)
                            : viewModel.lastRecoveryTranscript
                        UIPasteboard.general.string = packet
                    } label: {
                        Label("Copy Recovery Packet",
                              systemImage: "clock.arrow.circlepath")
                    }

                    Button {
                        UIPasteboard.general.string =
                            PersistentLogStore.shared.readAll() ?? ""
                    } label: {
                        Label("Copy Full Disk Log", systemImage: "doc.text")
                    }

                    Button {
                        showHour = true
                    } label: {
                        Label("Logs from the last hour", systemImage: "clock")
                    }

                    Button {
                        PersistentLogStore.shared.clear()
                    } label: {
                        Label("Clear Disk Logs", systemImage: "trash")
                            .foregroundColor(.red)
                    }
                }
            }
            .sheet(isPresented: $showHour) {
                HourLogGallery()
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
            .preferredColorScheme(.dark)
    }
}

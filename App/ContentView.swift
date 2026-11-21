//
//  ContentView.swift
//  Lum1na
//
//  Entry hosts the v2 TabView shell. Legacy Dummy RootView remains in-tree
//  but is no longer the primary chrome. Knob editor + Settings live inside V2.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        LuminaRootView()
    }
}

// MARK: - Legacy sheets kept for any residual call sites / previews

struct AllExploitsSheet: View {
    @ObservedObject var viewModel: ExploitManager
    @Environment(\.dismiss) var dismiss
    @State private var knobEntryId: String?
    @State private var knobEntryName = ""
    @State private var knobText = ""
    @State private var showKnobAlert = false

    private func knobValue(_ id: String) -> String {
        var buf: [CChar] = Array(repeating: 0, count: 256)
        return LabKnobRead(id, &buf, 256) == 1
            ? String(cString: buf) : ""
    }

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("ARMORY - ARM FILE GATES (PERSIST ACROSS BOOTS)"),
                        footer: Text("Marker files in Documents. Presence-only law - readers never parse content. Gates survive reboots; PANIC-POSSIBLE stages want one tap per fresh boot.")) {
                    ForEach(ArmGate.gates) { gate in
                        Toggle(isOn: Binding(
                            get: { ArmGate.isSet(gate.file) },
                            set: { ArmGate.set(gate.file, armed: $0) }
                        )) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(gate.title)
                                    .font(.system(.subheadline, weight: .semibold))
                                    .foregroundColor(.primary)
                                Text(gate.file + " - " + gate.note)
                                    .font(.system(.caption, design: .rounded))
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
                Section(header: Text("EXPLOIT CATALOG - TAP TO RUN INDIVIDUALLY")) {
                    ForEach(ExploitManager.catalog) { entry in
                        Button {
                            dismiss()
                            Task { await viewModel.executeExploit(entry) }
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
                                Image(systemName: "play.circle")
                                    .foregroundColor(entry.stage.color.opacity(0.7))
                            }
                        }
                        .disabled(viewModel.isRunning)
                        .contextMenu {
                            Button {
                                knobEntryId = entry.id
                                knobEntryName = entry.name
                                knobText = knobValue(entry.id)
                                showKnobAlert = true
                            } label: {
                                Label("Edit knob…", systemImage: "slider.horizontal.3")
                            }
                        }
                    }
                }
            }
            .navigationTitle("All Exploits")
            .navigationBarTitleDisplayMode(.inline)
            .alert("Knob — \(knobEntryName)", isPresented: $showKnobAlert) {
                TextField("e.g. pid / resid / untagged", text: $knobText)
                Button("Save") {
                    if let id = knobEntryId { LabKnobWrite(id, knobText) }
                }
                Button("Clear", role: .destructive) {
                    if let id = knobEntryId { LabKnobWrite(id, "") }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Input value used by this test at tap time (empty = stock behavior).")
            }
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
                        UIPasteboard.general.string = LabDeviceProfile.identBlock()
                    } label: {
                        Label("Copy Ident Block", systemImage: "doc.on.doc")
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

                Section(header: Text("RECOVERY LOG")) {
                    Button { showHour = true } label: {
                        Label("Logs from the last hour", systemImage: "clock")
                    }
                }
            }
            .sheet(isPresented: $showHour) { HourLogGallery() }
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

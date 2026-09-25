//
//  ContentView.swift
//  Lum1na
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = ExploitManager.shared
    @State private var showingAllExploits = false
    @State private var showingSettings = false
    @State private var recoveredNote: String = ""

    var body: some View {
        ZStack {
            GalaxyFieldView(accent: visualStage.color)

            VStack(spacing: 0) {
                headerSection
                    .padding(.top, 8)
                    .padding(.horizontal, 16)

                if !recoveredNote.isEmpty {
                    recoveryBanner
                        .padding(.top, 8)
                }

                MotherboardView(manager: viewModel) { stage in
                    Task { await viewModel.executeStage(stage.rawValue) }
                }
                .frame(height: 268)
                .padding(.horizontal, 8)
                .padding(.top, 4)

                MatrixConsoleView()
                    .padding(.horizontal, 16)
                    .padding(.top, 8)

                VStack(spacing: 10) {
                    jailbreakButton
                    allExploitsButton
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
                .padding(.bottom, 18)
            }
        }
        .preferredColorScheme(.dark)
        .sheet(isPresented: $showingAllExploits) {
            AllExploitsSheet(viewModel: viewModel)
        }
        .sheet(isPresented: $showingSettings) {
            SettingsSheet(viewModel: viewModel)
        }
        .onAppear {
            if viewModel.lastRecoverySummary.isEmpty == false {
                recoveredNote = "Recovered from crash: \(viewModel.lastRecoverySummary)"
            }
        }
    }

    private var visualStage: JailbreakStage {
        guard viewModel.isRunning else {
            return viewModel.lastResult.isSuccess ? .success : .idle
        }
        switch viewModel.selectedStage {
        case .kernel?: return .kaslr
        case .sandbox?: return .heap
        case .daemon?: return .ppl
        case .patchset?: return .persistence
        default: return .detecting
        }
    }

    private var recoveryBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.consoleWarning)
            Text(recoveredNote)
                .font(.system(.caption, design: .rounded))
                .foregroundColor(.consoleWarning)
                .lineLimit(3)
            Spacer()
            Button {
                UIPasteboard.general.string = viewModel.lastRecoveryTranscript
                recoveredNote = "Recovery packet copied (last TAP \(viewModel.lastRecoverySummary))"
            } label: {
                Text("Copy")
                    .font(.system(.caption, design: .rounded, weight: .semibold))
                    .foregroundColor(.lum1naCyan)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .luminaGlassRect(12)
        .padding(.horizontal, 16)
    }

    private var headerSection: some View {
        VStack(spacing: 8) {
            ZStack {
                VStack(spacing: 2) {
                    Text("LUM1NA")
                        .font(.system(size: 28, weight: .bold, design: .rounded))
                        .tracking(4)
                        .foregroundStyle(
                            LinearGradient(
                                colors: [.lum1naViolet, .white, .lum1naCyan],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                    Text("The guiding light for Jailbreaks")
                        .font(.system(size: 11, weight: .medium, design: .rounded))
                        .italic()
                        .foregroundColor(Color.white.opacity(0.45))
                }
                HStack {
                    Spacer()
                    Button(action: { showingSettings = true }) {
                        Image(systemName: "gearshape.fill")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundColor(.white.opacity(0.9))
                            .frame(width: 36, height: 36)
                            .luminaGlassCapsule()
                    }
                }
            }
            HStack(spacing: 10) {
                devicePill
                HStack(spacing: 6) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 7, height: 7)
                    Text(viewModel.isRunning ? "Running" : "Ready")
                        .font(.system(size: 11, weight: .semibold, design: .rounded))
                        .foregroundColor(statusColor)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .luminaGlassCapsule()
            }
        }
    }

    private var devicePill: some View {
        HStack(spacing: 6) {
            Image(systemName: "iphone")
                .font(.system(size: 11, weight: .semibold))
            Text(DeviceUtils.headerDeviceLine)
                .font(.system(size: 10, weight: .semibold, design: .rounded))
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .foregroundColor(.white.opacity(0.9))
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .luminaGlassCapsule()
    }

    private var jailbreakButton: some View {
        Button(action: {
            Task { await viewModel.executeStage("Full Chain") }
        }) {
            HStack(spacing: 10) {
                Image(systemName: "sparkle")
                    .font(.body.weight(.semibold))
                Text("JAILBREAK")
                    .font(.system(.subheadline, design: .rounded, weight: .bold))
                    .tracking(1.2)
                if viewModel.isRunning {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        .scaleEffect(0.8)
                }
            }
            .foregroundColor(.white)
            .frame(maxWidth: .infinity)
            .frame(height: 52)
            .luminaGlassRect(16)
        }
        .disabled(viewModel.isRunning)
    }

    private var allExploitsButton: some View {
        Button(action: { showingAllExploits = true }) {
            HStack(spacing: 6) {
                Text("All stages")
                    .font(.system(.subheadline, weight: .medium))
                Image(systemName: "chevron.down")
                    .font(.caption)
            }
            .foregroundColor(.lum1naCyan)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .luminaGlassCapsule()
        }
        .disabled(viewModel.isRunning)
    }

    private var statusColor: Color {
        if viewModel.lastResult.isSuccess { return .consoleSuccess }
        return viewModel.isRunning ? visualStage.color : .gray
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

    private func boardLeakLabel() -> String {
        let leaks = Lum1naBoard.shared().leaks
        var hits = 0
        for case let e as NSDictionary in leaks {
            let n = (e["hits"] as? NSNumber)?.intValue ?? 1
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
                        PersistentLogStore.shared.clear()
                    } label: {
                        Label("Clear Disk Logs", systemImage: "trash")
                            .foregroundColor(.red)
                    }
                }
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

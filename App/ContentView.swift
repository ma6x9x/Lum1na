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
            CircuitBackgroundView(stage: visualStage)
            GlyphRainView(intensity: viewModel.isRunning ? 0.55 : 0.22)

            VStack(spacing: 0) {
                headerSection
                    .padding(.top, 10)
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
                .padding(.bottom, 16)

                RainbowWaveRibbonView(power: viewModel.isRunning ? 1.0 : 0.28)
                    .frame(height: 28)
                    .allowsHitTesting(false)
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
                let tap = PersistentLogStore.shared.lastTapId().map { " last TAP \($0)" } ?? ""
                recoveredNote = "Recovered from crash\(tap): \(viewModel.lastRecoverySummary)"
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
                .lineLimit(2)
            Spacer()
            Button {
                UIPasteboard.general.string =
                    PersistentLogStore.shared.recoveryTranscript()
                viewModel.log("[+] Recovery transcript copied", level: .success)
            } label: {
                Text("Copy")
                    .font(.system(.caption, weight: .semibold))
                    .foregroundColor(.lum1naCyan)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.consoleWarning.opacity(0.08))
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(Color.consoleWarning.opacity(0.3), lineWidth: 1)
                )
        )
        .padding(.horizontal, 16)
    }

    private var headerSection: some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                ZStack(alignment: .topLeading) {
                    CloudWispsView()
                        .offset(x: 36, y: -10)
                    HStack(spacing: 8) {
                        Lum1naStarShape()
                            .fill(
                                LinearGradient(
                                    colors: [Color.lum1naMagenta, Color.white, Color.lum1naCyan],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .frame(width: 22, height: 22)
                            .shadow(color: Color.lum1naCyan.opacity(0.6), radius: 6)
                        Text("Lum1na")
                            .font(.system(size: 32, weight: .bold, design: .rounded))
                            .foregroundStyle(
                                LinearGradient(
                                    colors: [.lum1naViolet, .lum1naCyan],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                    }
                }
                Text("The guiding light for Jailbreaks")
                    .font(.system(size: 11, weight: .medium, design: .rounded))
                    .italic()
                    .foregroundColor(Color.white.opacity(0.45))
                    .padding(.leading, 30)
            }

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 8) {
                HStack(spacing: 8) {
                    devicePill
                    Button(action: { showingSettings = true }) {
                        Image(systemName: "gearshape.fill")
                            .font(.title3)
                            .foregroundColor(.lum1naCyan)
                    }
                }
                HStack(spacing: 6) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 7, height: 7)
                        .shadow(color: statusColor.opacity(0.5), radius: 3)
                    Text(viewModel.isRunning ? "Running..." : "Ready")
                        .font(.system(.caption, design: .rounded, weight: .medium))
                        .foregroundColor(statusColor)
                }
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
        .foregroundColor(.white.opacity(0.85))
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(
            Capsule()
                .fill(Color.white.opacity(0.06))
                .overlay(
                    Capsule().stroke(Color.lum1naViolet.opacity(0.45), lineWidth: 1)
                )
        )
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
            .background(
                RoundedRectangle(cornerRadius: 14)
                    .fill(
                        LinearGradient(
                            colors: viewModel.isRunning
                                ? [Color.gray.opacity(0.35), Color.gray.opacity(0.18)]
                                : [Color.lum1naCyan.opacity(0.85), Color.lum1naMagenta.opacity(0.85)],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(Color.white.opacity(viewModel.isRunning ? 0.15 : 0.35), lineWidth: 1)
                    )
            )
            .shadow(
                color: (viewModel.isRunning ? Color.clear : Color.lum1naCyan.opacity(0.35)),
                radius: 10
            )
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
            .background(
                Capsule()
                    .fill(Color.lum1naCyan.opacity(0.1))
                    .overlay(
                        Capsule()
                            .stroke(Color.lum1naCyan.opacity(0.3), lineWidth: 1)
                    )
            )
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

                Section(header: Text("RECOVERY LOG")) {
                    Button {
                        UIPasteboard.general.string =
                            PersistentLogStore.shared.recoveryTranscript()
                    } label: {
                        Label("Copy Recovery Log",
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
                        Label("Clear Log", systemImage: "trash")
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

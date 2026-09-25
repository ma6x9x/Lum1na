//
//  ContentView.swift
//  Lum1na
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = ExploitManager.shared
    @State private var showingAllExploits = false
    @State private var showingSettings = false

    var body: some View {
        VStack(spacing: 0) {
            headerSection
                .padding(.top, 12)
                .padding(.horizontal, 20)

            // Console takes all remaining space
            MatrixConsoleView()
                .padding(.horizontal, 16)
                .padding(.top, 10)

            // Bottom control deck
            VStack(spacing: 12) {
                HStack(spacing: 16) {
                    ForEach(ExploitManager.catalog) { entry in
                        Button {
                            Task { await viewModel.executeExploit(entry) }
                        } label: {
                            HexagonBadgeView(
                                type: badgeType(for: entry.stage),
                                isActive: viewModel.isRunning &&
                                    viewModel.selectedStage == entry.stage
                            )
                        }
                        .buttonStyle(PlainButtonStyle())
                        .disabled(viewModel.isRunning)
                    }
                }

                fullChainButton

                allExploitsButton
            }
            .padding(.horizontal, 16)
            .padding(.top, 10)
            .padding(.bottom, 20)

            RainbowWaveRibbonView(power: viewModel.isRunning ? 1.0 : 0.3)
                .frame(height: 40)
                .allowsHitTesting(false)
        }
        .sheet(isPresented: $showingAllExploits) {
            AllExploitsSheet(viewModel: viewModel)
        }
        .sheet(isPresented: $showingSettings) {
            SettingsSheet(viewModel: viewModel)
        }
    }

    private func badgeType(for stage: ExploitStage) -> BadgeType {
        switch stage {
        case .kernel: return .kernel
        case .sandbox: return .sandbox
        case .daemon: return .daemon
        case .patchset: return .patchset
        }
    }

    private var headerSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Lum1na")
                    .font(.system(size: 42, weight: .bold, design: .rounded))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [.lum1naViolet, .lum1naCyan],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    )

                HStack(spacing: 8) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 8, height: 8)
                        .shadow(color: statusColor.opacity(0.5), radius: 4)

                    Text(viewModel.isRunning ? "Running..." : "Ready")
                        .font(.system(.subheadline, weight: .medium))
                        .foregroundColor(statusColor)
                }
            }

            Spacer()

            Button(action: { showingSettings = true }) {
                Image(systemName: "gearshape.fill")
                    .font(.title3)
                    .foregroundColor(.lum1naCyan)
            }
        }
    }

    private var fullChainButton: some View {
        Button(action: {
            Task { await viewModel.executeStage("Full Chain") }
        }) {
            HStack(spacing: 12) {
                Image(systemName: "bolt.fill")
                    .font(.system(.body, weight: .semibold))

                Text("Execute Full Chain")
                    .font(.system(.subheadline, weight: .bold))

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
                            colors: [
                                viewModel.isRunning ? Color.gray.opacity(0.3) : currentStage.color.opacity(0.25),
                                viewModel.isRunning ? Color.gray.opacity(0.15) : currentStage.color.opacity(0.1)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(
                                viewModel.isRunning ? Color.gray.opacity(0.5) : currentStage.color.opacity(0.6),
                                lineWidth: 1.5
                            )
                    )
            )
oge        }
        .disabled(viewModel.isRunning)
    }

    private var allExploitsButton: some View {
        Button(action: { showingAllExploits = true }) {
            HStack(spacing: 6) {
                Text("All Exploits")
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
    }

    private var currentStage: JailbreakStage {
        guard viewModel.isRunning else {
            return viewModel.lastResult.isSuccess ? .success : .idle
        }
        switch viewModel.selectedStage {
        case .kernel?: return .ane
        case .sandbox?: return .krw
        case .daemon?: return .ppl
        case .patchset?: return .persistence
        default: return .detecting
        }
    }

    private var statusColor: Color {
        if viewModel.lastResult.isSuccess { return .consoleSuccess }
        return viewModel.isRunning ? currentStage.color : .gray
    }
}

struct AllExploitsSheet: View {
    @ObservedObject var viewModel: ExploitManager
    @Environment(\.dismiss) var dismiss

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("EXPLOIT CATALOG — TAP TO RUN INDIVIDUALLY")) {
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

                                if viewModel.isRunning && viewModel.selectedStage == entry.stage {
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

                Section(footer: Text("Run exploits one at a time to isolate crashes. Console records every step.")) {
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
                    LabeledContent("Machine", value: DeviceUtils.currentDevice)
                    LabeledContent("Category", value: DeviceUtils.deviceCategory)
                    LabeledContent("Chip", value: DeviceUtils.currentChip)
                    LabeledContent("Supported", value: DeviceUtils.isSupported ? "Yes" : "No")
                }

                Section(header: Text("EXPLOIT STATE")) {
                    LabeledContent("Kernel Slide", value: viewModel.currentKernelSlide != 0
                        ? "0x\(String(viewModel.currentKernelSlide, radix: 16, uppercase: true))"
                        : "Not obtained")
                    LabeledContent("Kernel Base", value: viewModel.currentKernelBase != 0
                        ? "0x\(String(viewModel.currentKernelBase, radix: 16, uppercase: true))"
                        : "Not obtained")
                    LabeledContent("Last Result", value: viewModel.lastResult.isSuccess ? "Success" : "Idle/Failure")
                }

                Section(header: Text("DEBUG")) {
                    Button {
                        UIPasteboard.general.string = viewModel.exportFullDebugLog()
                    } label: {
                        Label("Copy Full Log", systemImage: "doc.on.clipboard")
                    }

                    Button {
                        viewModel.clearConsole()
                    } label: {
                        Label("Clear Console", systemImage: "trash")
                            .foregroundColor(.red)
                    }

                    Button {
                        viewModel.reset()
                    } label: {
                        Label("Reset State", systemImage: "arrow.counterclockwise")
                            .foregroundColor(.orange)
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

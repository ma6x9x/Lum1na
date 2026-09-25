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
        VStack(spacing: 0) {
            headerSection
                .padding(.top, 12)
                .padding(.horizontal, 20)

            if !recoveredNote.isEmpty {
                recoveryBanner
            }

            MatrixConsoleView()
                .padding(.horizontal, 16)
                .padding(.top, 10)

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
        .onAppear {
            if viewModel.lastRecoverySummary.isEmpty == false {
                recoveredNote = "Recovered from crash: \(viewModel.lastRecoverySummary)"
            }
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

    private func badgeType(for stage: ExploitStage) -> BadgeType {
        switch stage {
        case .kernel: return .kernel
        case .sandbox: return .sandbox
        case .daemon: return .daemon
        case .patchset: return .patchset
        }
    }

//
//  ContentView.swift
//  Lum1na - Fixed for compilation
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()
    @State private var showingStageTester = false
    
    var body: some View {
        ZStack {
            Color.black.opacity(0.9).ignoresSafeArea()
            
            VStack(spacing: 0) {
                HeaderView()
                    .padding(.top, 12)
                
                // Fixed: Proper device info access
                DeviceInfoSection(viewModel: viewModel)
                    .padding(.horizontal, 20)
                    .padding(.top, 8)
                
                // Use the separate StarBeaconView file, not inline
                StarBeaconSection(viewModel: viewModel)
                    .padding(.top, 10)
                
                Text("The guiding light for Jailbreaks")
                    .font(.system(size: 13))
                    .foregroundColor(.gray)
                    .padding(.top, 8)
                
                ConsoleCard(viewModel: viewModel)
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
                
                StageButtonsRow(viewModel: viewModel)
                    .padding(.horizontal, 12)
                    .padding(.top, 8)
                
                ActionButtons(viewModel: viewModel, showingStageTester: $showingStageTester)
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
                    .padding(.bottom, 16)
            }
        }
        .sheet(isPresented: $showingStageTester) {
            StageTesterView(viewModel: viewModel)
        }
    }
}

// MARK: - Header
struct HeaderView: View {
    var body: some View {
        VStack(spacing: 2) {
            Text("Lum1na")
                .font(.system(size: 32, weight: .bold, design: .rounded))
                .foregroundColor(.white)
            
            Text("v0.1 • Multi-Path")
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(.gray)
        }
    }
}

// MARK: - Device Info Section (Fixed)
struct DeviceInfoSection: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "iphone")
                .font(.system(size: 14))
                .foregroundColor(.blue)
            
            VStack(alignment: .leading, spacing: 1) {
                // Fixed: deviceInfo is optional, use proper optional binding
                if let info = viewModel.deviceInfo {
                    Text(info.machine.isEmpty ? "Unknown" : info.machine)
                        .font(.system(size: 13, weight: .semibold))
                    Text("iOS \(info.version)")
                        .font(.system(size: 11))
                        .foregroundColor(.gray)
                } else {
                    Text("Detecting...")
                        .font(.system(size: 13, weight: .semibold))
                    Text("iOS ?")
                        .font(.system(size: 11))
                        .foregroundColor(.gray)
                }
            }
            
            Spacer()
            
            HStack(spacing: 4) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 6, height: 6)
                Text(viewModel.exploitState.description)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(statusColor)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.white.opacity(0.1))
        )
        .frame(maxWidth: 260, alignment: .center)
    }
    
    private var statusColor: Color {
        switch viewModel.exploitState {
        case .idle: return .gray
        case .preparing: return .orange
        case .executingKernel, .executingSandbox, .executingDaemon, .executingPatchset: return .blue
        case .success: return .green
        case .failed: return .red
        }
    }
}


// Replace StarBeaconView with simple text
Text("★")
    .font(.system(size: 60))
    .foregroundColor(.blue)

// MARK: - Console Card
struct ConsoleCard: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label("console", systemImage: "terminal")
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .foregroundColor(.gray)
                
                Spacer()
                
                Button(action: { UIPasteboard.general.string = viewModel.consoleText }) {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 12))
                        .foregroundColor(.gray)
                }
                
                Button(action: { viewModel.clearConsole() }) {
                    Image(systemName: "trash")
                        .font(.system(size: 12))
                        .foregroundColor(.gray)
                        .padding(.leading, 8)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            
            Divider().background(Color.white.opacity(0.1))
            
            ScrollView(.vertical, showsIndicators: true) {
                Text(viewModel.consoleText)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(Color(red: 0, green: 0.8, blue: 1)) // Custom cyan
                    .lineSpacing(2)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .frame(height: 140)
        }
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(Color.white.opacity(0.05))
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color.pink.opacity(0.3), lineWidth: 1)
                )
        )
    }
}

// MARK: - Stage Buttons
struct StageButtonsRow: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    let stages = [
        ("KERNEL", "cpu", ExploitState.executingKernel),
        ("SANDBOX", "lock.open", ExploitState.executingSandbox),
        ("DAEMON", "gear", ExploitState.executingDaemon),
        ("PATCHSET", "checkmark.shield", ExploitState.executingPatchset)
    ]
    
    var body: some View {
        HStack(spacing: 6) {
            ForEach(stages, id: \.0) { stage in
                VStack(spacing: 4) {
                    Image(systemName: stage.1)
                        .font(.system(size: 12))
                    Text(stage.0)
                        .font(.system(size: 9, weight: .medium))
                }
                .foregroundColor(isActive(stage.2) ? Color(red: 0, green: 0.8, blue: 1) : .gray)
                .frame(width: 70, height: 44)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.white.opacity(0.05))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(isActive(stage.2) ? Color.blue : Color.clear, lineWidth: 1)
                )
            }
        }
    }
    
    private func isActive(_ state: ExploitState) -> Bool {
        return viewModel.exploitState == state
    }
}

// MARK: - Action Buttons
struct ActionButtons: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @Binding var showingStageTester: Bool
    
    var body: some View {
        HStack(spacing: 12) {
            Button(action: { showingStageTester = true }) {
                Label("Test Stages", systemImage: "slider.horizontal.3")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .background(
                        RoundedRectangle(cornerRadius: 22)
                            .fill(Color.white.opacity(0.1))
                    )
            }
            
            Button(action: {
                Task { await viewModel.executeStage("Full Chain") }
            }) {
                Text("Jailbreak")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .background(
                        RoundedRectangle(cornerRadius: 22)
                            .fill(
                                LinearGradient(
                                    colors: [.pink, .purple],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                    )
            }
            .disabled(viewModel.isRunning)
        }
    }
}

// MARK: - Stage Tester View
struct StageTesterView: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @Environment(\.presentationMode) var presentationMode
    
    let stages = [
        ("KERNEL", "KASLR + P044", "cpu"),
        ("SANDBOX", "CVE-2026-65343", "lock.open"),
        ("DAEMON", "Service Injection", "gear"),
        ("PATCHSET", "Final Rooting", "checkmark.shield")
    ]
    
    var body: some View {
        NavigationView {
            List {
                Section(header: Text("Individual Stage Testing")) {
                    ForEach(stages, id: \.0) { stage in
                        Button(action: {
                            Task {
                                await viewModel.executeStage(stage.0)
                            }
                            presentationMode.wrappedValue.dismiss()
                        }) {
                            HStack(spacing: 12) {
                                Image(systemName: stage.2)
                                    .font(.system(size: 20))
                                    .foregroundColor(.blue)
                                    .frame(width: 40, height: 40)
                                    .background(Color.blue.opacity(0.1))
                                    .cornerRadius(10)
                                
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(stage.0)
                                        .font(.system(size: 16, weight: .semibold))
                                    Text(stage.1)
                                        .font(.system(size: 12))
                                        .foregroundColor(.gray)
                                }
                                
                                Spacer()
                                
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 14))
                                    .foregroundColor(.gray)
                            }
                        }
                    }
                }
                
                Section {
                    Button("Reset State") { viewModel.reset() }
                        .foregroundColor(.red)
                }
                
                Section(header: Text("Recovery")) {
                    if viewModel.recoveryAvailable {
                        Button("Attempt Recovery") {
                            viewModel.attemptRecovery()
                            presentationMode.wrappedValue.dismiss()
                        }
                        .foregroundColor(.orange)
                    }
                    
                    Button("Export Recovery Logs") {
                        let logs = viewModel.exportRecoveryLogs()
                        UIPasteboard.general.string = logs
                    }
                }
            }
            .navigationTitle("Stage Tester")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { presentationMode.wrappedValue.dismiss() }
                }
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

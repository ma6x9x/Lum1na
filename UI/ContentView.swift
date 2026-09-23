//
//  ContentView.swift
//  Lum1na - iOS 14.0 Compatible
//

import SwiftUI

// MARK: - iOS 14 Compatible Colors
extension Color {
    static let luminaCyan = Color(red: 0.0, green: 0.8, blue: 1.0)  // Replaces .cyan
    static let luminaMint = Color(red: 0.0, green: 1.0, blue: 0.6)  // Replaces .mint
}

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()
    @State private var showingStageTester = false
    
    var body: some View {
        ZStack {
            // Background
            Color.black.opacity(0.9).ignoresSafeArea()
            
            VStack(spacing: 0) {
                // Header
                HeaderView()
                    .padding(.top, 12)
                
                // Device Info - Fixed for iOS 14
                DeviceInfoSection(viewModel: viewModel)
                    .padding(.horizontal, 20)
                    .padding(.top, 8)
                
                // Star Beacon
                StarBeaconSection(viewModel: viewModel)
                    .padding(.top, 10)
                
                Text("The guiding light for Jailbreaks")
                    .font(.system(size: 13))
                    .foregroundColor(.gray)
                    .padding(.top, 8)
                
                // Console
                ConsoleCard(viewModel: viewModel)
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
                
                // Stage Buttons (4 stages matching your selector)
                StageButtonsRow(viewModel: viewModel)
                    .padding(.horizontal, 12)
                    .padding(.top, 8)
                
                // Action Buttons
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

// MARK: - Device Info Section (Fixed for iOS 14)
struct DeviceInfoSection: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "iphone")
                .font(.system(size: 14))
                .foregroundColor(.blue)
            
            VStack(alignment: .leading, spacing: 1) {
                // Fixed: deviceInfo is not optional, check if empty
                Text(deviceInfoText)
                    .font(.system(size: 13, weight: .semibold))
                Text("iOS \(viewModel.deviceInfo?.version ?? "?")")
                    .font(.system(size: 11))
                    .foregroundColor(.gray)
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
            // iOS 14 compatible - no .ultraThinMaterial
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.white.opacity(0.1))
        )
        .frame(maxWidth: 260, alignment: .center)
    }
    
    // Fixed: Handle non-optional deviceInfo
    private var deviceInfoText: String {
        let machine = viewModel.deviceInfo?.machine ?? ""
        return machine.isEmpty ? "Detecting..." : machine
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

// MARK: - Star Beacon Section
struct StarBeaconSection: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        ZStack {
            Circle()
                .stroke(
                    LinearGradient(
                        colors: [.pink, .blue],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 2
                )
                .frame(width: 130, height: 130)
            
            // iOS 14 compatible fill
            Circle()
                .fill(Color.white.opacity(0.05))
                .frame(width: 120, height: 120)
            
            StarBeaconView(state: viewModel.exploitState)
                .frame(width: 80, height: 80)
        }
        .frame(height: 140)
    }
}

// MARK: - Star Beacon View
struct StarBeaconView: View {
    let state: ExploitState
    
    var body: some View {
        GeometryReader { geometry in
            let center = CGPoint(x: geometry.size.width / 2, y: geometry.size.height / 2)
            let radius = min(geometry.size.width, geometry.size.height) / 2
            
            ZStack {
                // Four-pointed star
                StarShape()
                    .fill(
                        LinearGradient(
                            colors: stateColors,
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .frame(width: radius * 1.5, height: radius * 1.5)
                
                // Center glow
                Circle()
                    .fill(Color.white.opacity(0.8))
                    .frame(width: radius * 0.3, height: radius * 0.3)
                    .shadow(color: stateColors[0].opacity(0.8), radius: 10)
            }
            .position(center)
        }
    }
    
    // iOS 14 compatible colors (no .cyan, .mint)
    private var stateColors: [Color] {
        switch state {
        case .idle: return [.gray, .gray]
        case .preparing: return [.orange, .yellow]
        case .executingKernel: return [.luminaCyan, .blue]  // Custom cyan
        case .executingSandbox: return [.purple, .pink]
        case .executingDaemon: return [.green, .luminaCyan]   // Custom cyan
        case .executingPatchset: return [.green, .luminaMint] // Custom mint
        case .success: return [.green, .green]
        case .failed: return [.red, .red]
        }
    }
}

// MARK: - Star Shape
struct StarShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let radius = min(rect.width, rect.height) / 2
        
        let points = [
            CGPoint(x: center.x, y: center.y - radius),
            CGPoint(x: center.x + radius * 0.3, y: center.y - radius * 0.3),
            CGPoint(x: center.x + radius, y: center.y),
            CGPoint(x: center.x + radius * 0.3, y: center.y + radius * 0.3),
            CGPoint(x: center.x, y: center.y + radius),
            CGPoint(x: center.x - radius * 0.3, y: center.y + radius * 0.3),
            CGPoint(x: center.x - radius, y: center.y),
            CGPoint(x: center.x - radius * 0.3, y: center.y - radius * 0.3),
        ]
        
        path.move(to: points[0])
        for i in 1..<points.count {
            path.addLine(to: points[i])
        }
        path.closeSubpath()
        
        return path
    }
}

// MARK: - Console Card (iOS 14 Compatible)
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
                    .foregroundColor(.luminaCyan) // Custom cyan
                    .lineSpacing(2)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .frame(height: 140)
        }
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(Color.white.opacity(0.05)) // iOS 14 compatible
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color.pink.opacity(0.3), lineWidth: 1)
                )
        )
    }
}

// MARK: - Stage Buttons Row (4 stages)
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
                .foregroundColor(stageColor(for: stage.2))
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
    
    private func stageColor(for state: ExploitState) -> Color {
        return isActive(state) ? .luminaCyan : .gray
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

// MARK: - Preview
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

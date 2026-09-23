//
//  ContentView.swift
//  Lum1na
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()
    @State private var showingStageTester = false
    
    var body: some View {
        ZStack {
            Color(hex: "07060F").ignoresSafeArea()
            
            VStack(spacing: 0) {
                // MARK: - Header
                HeaderView()
                    .padding(.top, 12)
                
                // MARK: - Device Info
                DeviceInfoCompact(viewModel: viewModel)
                    .padding(.horizontal, 20)
                    .padding(.top, 8)
                
                // MARK: - Star Beacon
                StarBeaconSection(viewModel: viewModel)
                    .padding(.top, 10)
                
                Text("The guiding light for Jailbreaks")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .padding(.top, 8)
                
                // MARK: - Console
                ConsoleCard(viewModel: viewModel)
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
                
                // MARK: - Stage Buttons (6 stages)
                StageButtonsRow(viewModel: viewModel)
                    .padding(.horizontal, 12)
                    .padding(.top, 8)
                
                // MARK: - Action Buttons
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

// MARK: - Header View
struct HeaderView: View {
    var body: some View {
        VStack(spacing: 2) {
            Text("Lum1na")
                .font(.system(size: 32, weight: .bold, design: .rounded))
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color(hex: "FF6B9D"), Color(hex: "4ECDC4")],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
            
            Text("v0.1 • ANE 254-Input")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(.gray)
        }
    }
}

// MARK: - Device Info
struct DeviceInfoCompact: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "iphone")
                .font(.system(size: 14))
                .foregroundStyle(Color(hex: "4ECDC4"))
            
            VStack(alignment: .leading, spacing: 1) {
                Text(viewModel.deviceInfo?.machine ?? "Detecting...")
                    .font(.system(size: 13, weight: .semibold))
                Text("iOS \(viewModel.deviceInfo?.version ?? "?")")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            HStack(spacing: 4) {
                Circle()
                    .fill(viewModel.statusColor)
                    .frame(width: 6, height: 6)
                Text(viewModel.statusText)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(viewModel.statusColor)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            Capsule()
                .fill(.ultraThinMaterial)
                .overlay(Capsule().stroke(Color.white.opacity(0.1), lineWidth: 1))
        )
        .frame(maxWidth: 260, alignment: .center)
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
                        colors: [Color(hex: "FF6B9D"), Color(hex: "4ECDC4")],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 2
                )
                .frame(width: 130, height: 130)
            
            Circle()
                .fill(.ultraThinMaterial)
                .frame(width: 120, height: 120)
            
            StarBeaconView(stage: currentStage)
                .frame(width: 80, height: 80)
        }
        .frame(height: 140)
    }
    
    private var currentStage: StarBeaconStage {
        switch viewModel.exploitState {
        case .idle: return .idle
        case .detecting, .preparing: return .detecting
        case .executingKASLR: return .kaslr
        case .executingHeap: return .heap
        case .executingANE: return .ane
        case .executingKRW: return .krw
        case .executingPPL: return .ppl
        case .executingPersistence: return .persistence
        case .success: return .success
        case .failed: return .failed
        }
    }
}

// MARK: - Star Beacon Stage Enum
enum StarBeaconStage {
    case idle, detecting, kaslr, heap, ane, krw, ppl, persistence, success, failed
}

// MARK: - Star Beacon View
struct StarBeaconView: View {
    let stage: StarBeaconStage
    
    var body: some View {
        GeometryReader { geometry in
            let center = CGPoint(x: geometry.size.width / 2, y: geometry.size.height / 2)
            let radius = min(geometry.size.width, geometry.size.height) / 2
            
            ZStack {
                // Four-pointed star
                StarShape()
                    .fill(
                        LinearGradient(
                            colors: stageColors,
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .frame(width: radius * 1.5, height: radius * 1.5)
                
                // Center glow
                Circle()
                    .fill(Color.white.opacity(0.8))
                    .frame(width: radius * 0.3, height: radius * 0.3)
                    .shadow(color: stageColors[0].opacity(0.8), radius: 10)
            }
            .position(center)
        }
    }
    
    private var stageColors: [Color] {
        switch stage {
        case .idle: return [.gray, .gray]
        case .detecting: return [.orange, .yellow]
        case .kaslr: return [.cyan, .blue]
        case .heap: return [.purple, .pink]
        case .ane: return [.green, .cyan]
        case .krw: return [.orange, .red]
        case .ppl: return [.red, .orange]
        case .persistence: return [.green, .mint]
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
        
        // Four-pointed star
        let points = [
            CGPoint(x: center.x, y: center.y - radius),      // Top
            CGPoint(x: center.x + radius * 0.3, y: center.y - radius * 0.3),
            CGPoint(x: center.x + radius, y: center.y),      // Right
            CGPoint(x: center.x + radius * 0.3, y: center.y + radius * 0.3),
            CGPoint(x: center.x, y: center.y + radius),      // Bottom
            CGPoint(x: center.x - radius * 0.3, y: center.y + radius * 0.3),
            CGPoint(x: center.x - radius, y: center.y),      // Left
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

// MARK: - Console Card
struct ConsoleCard: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label("console", systemImage: "terminal")
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
                
                Spacer()
                
                Button(action: { UIPasteboard.general.string = viewModel.consoleText }) {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                
                Button(action: { viewModel.clearConsole() }) {
                    Image(systemName: "trash")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .padding(.leading, 8)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            
            Divider().background(Color.white.opacity(0.1))
            
            ScrollView(.vertical, showsIndicators: true) {
                Text(viewModel.consoleText)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.cyan)
                    .lineSpacing(2)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .frame(height: 140)
        }
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color(hex: "FF6B9D").opacity(0.3), lineWidth: 1)
                )
        )
    }
}

// MARK: - Stage Buttons Row (6 stages)
struct StageButtonsRow: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    let stages = [
        ("KASLR", "memorychip"),
        ("Heap", "cpu"),
        ("ANE", "brain"),
        ("KRW", "arrow.left.arrow.right"),
        ("PPL", "lock.shield"),
        ("Persist", "arrow.clockwise")
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
                .foregroundStyle(viewModel.stageColor(for: stage.0))
                .frame(width: 48, height: 40)
                .background(
                    Capsule()
                        .fill(.ultraThinMaterial)
                        .overlay(Capsule().stroke(Color.white.opacity(0.1), lineWidth: 1))
                )
            }
        }
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
                    .foregroundStyle(.primary)
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .background(Capsule().fill(.ultraThinMaterial))
            }
            
            Button(action: { viewModel.startJailbreak() }) {
                Text("Jailbreak")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .background(
                        Capsule().fill(
                            LinearGradient(
                                colors: [Color(hex: "FF6B9D"), Color(hex: "9B59B6")],
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
    @Environment(\.dismiss) var dismiss
    
    let stages = [
        ("KASLR Bypass", "memorychip", "Test KASLR leak via ANE"),
        ("Heap Corruption", "cpu", "Test UPL leak primitive"),
        ("ANE Exploit", "brain", "Test ANE 254-input OOB"),
        ("KRW Verify", "arrow.left.arrow.right", "Test kernel R/W"),
        ("PPL Bypass", "lock.shield", "Test PPL defeat"),
        ("Persistence", "arrow.clockwise", "Test tempRoot install")
    ]
    
    var body: some View {
        NavigationView {
            List {
                Section(header: Text("Individual Stage Testing")) {
                    ForEach(stages, id: \.0) { stage in
                        Button(action: {
                            viewModel.testIndividualStage(stage.0)
                            dismiss()
                        }) {
                            HStack(spacing: 12) {
                                Image(systemName: stage.1)
                                    .font(.system(size: 20))
                                    .foregroundStyle(Color(hex: "FF6B9D"))
                                    .frame(width: 40, height: 40)
                                    .background(Color(hex: "FF6B9D").opacity(0.1))
                                    .cornerRadius(10)
                                
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(stage.0)
                                        .font(.system(size: 16, weight: .semibold))
                                    Text(stage.2)
                                        .font(.system(size: 12))
                                        .foregroundStyle(.secondary)
                                }
                                
                                Spacer()
                                
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 14))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                
                Section {
                    Button("Reset State") { viewModel.reset() }
                        .foregroundStyle(.red)
                }
                
                Section(header: Text("Device Info")) {
                    LabeledContent("Machine", value: viewModel.deviceInfo?.machine ?? "Unknown")
                    LabeledContent("iOS Version", value: viewModel.deviceInfo?.version ?? "?")
                    LabeledContent("Build", value: viewModel.deviceInfo?.build ?? "?")
                    LabeledContent("Kernel Slide", value: viewModel.currentKernelSlide != 0 ? 
                        "0x\(String(viewModel.currentKernelSlide, radix: 16))" : "Not set")
                }
            }
            .navigationTitle("Stage Tester")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

// MARK: - Color Extension
extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3: // RGB (12-bit)
            (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: // RGB (24-bit)
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: // ARGB (32-bit)
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (1, 1, 1, 0)
        }
        self.init(.sRGB, red: Double(r) / 255, green: Double(g) / 255, blue: Double(b) / 255, opacity: Double(a) / 255)
    }
}

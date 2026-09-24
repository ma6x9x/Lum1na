//
//  ContentView.swift
//  Lum1na - Complete Liquid Glass Integration
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()
    @StateObject private var bubbleMotion = LiquidBubbleMotionState()
    @State private var showingAllExploits = false
    @State private var selectedStage: ExploitChainStage?
    
    // Calculate current JailbreakStage from viewModel state
    private var currentStage: JailbreakStage {
        switch viewModel.exploitState {
        case .idle: return .idle
        case .preparing: return .detecting
        case .executingKernel: return .ane
        case .executingSandbox: return .krw
        case .executingDaemon: return .ppl
        case .executingPatchset: return .persistence
        case .success: return .success
        case .failed: return .failed
        }
    }
    
    // Calculate active badges based on exploit state
    private var activeBadges: Set<BadgeType> {
        var badges: Set<BadgeType> = []
        switch viewModel.exploitState {
        case .executingKernel, .executingSandbox, .executingDaemon, .executingPatchset, .success:
            badges.insert(.kernel)
            fallthrough
        case .executingSandbox, .executingDaemon, .executingPatchset, .success:
            badges.insert(.sandbox)
            fallthrough
        case .executingDaemon, .executingPatchset, .success:
            badges.insert(.daemon)
            fallthrough
        case .executingPatchset, .success:
            badges.insert(.patchset)
        default: break
        }
        return badges
    }
    
    var body: some View {
        ZStack {
            // MARK: - Layer 1: Circuit Background (Base)
            CircuitBackgroundView(stage: currentStage)
                .ignoresSafeArea()
            
            // MARK: - Layer 2: Glyph Rain Overlay (30% opacity)
            GlyphRainView(intensity: 0.3)
                .opacity(0.3)
            
            // MARK: - Main Content
            VStack(spacing: 0) {
                // Header
                headerSection
                
                // Central Star Beacon
                StarBeaconView(stage: currentStage)
                    .frame(height: 120)
                    .padding(.vertical, 10)
                
                // Hexagon Badges for Stages
                BadgeContainerView(activeBadges: activeBadges, stage: currentStage)
                    .padding(.vertical, 8)
                
                // Heap Address Display
                CentralHeapView(
                    heapAddress: viewModel.currentKernelSlide != 0 
                        ? "0x\(String(viewModel.currentKernelSlide, radix: 16, uppercase: true))" 
                        : nil,
                    stage: currentStage
                )
                .padding(.vertical, 8)
                
                // MARK: - Layer 3: Liquid Bubble Motion Particles
                liquidBubblesSection
                    .frame(height: 60)
                
                // Matrix Console
                MatrixConsoleView()
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                
                Spacer(minLength: 10)
                
                // Exploit Stage Selector (using ExploitStageSelector component)
                ExploitStageSelector(
                    selectedStage: $selectedStage,
                    isRunning: viewModel.isRunning,
                    onStageSelected: { stage in
                        Task { await viewModel.executeStage(stage.rawValue) }
                    }
                )
                .padding(.horizontal, 16)
                
                // Execute Full Chain Button
                fullChainButton
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                
                // All Exploits Button
                allExploitsButton
                    .padding(.bottom, 20)
            }
            
            // MARK: - Layer 4: Rainbow Wave Ribbon (Bottom)
            VStack {
                Spacer()
                RainbowWaveRibbonView(power: viewModel.isRunning ? 1.0 : 0.3)
                    .frame(height: 60)
                    .padding(.bottom, 8)
            }
            .allowsHitTesting(false)
        }
        .sheet(isPresented: $showingAllExploits) {
            AllExploitsSheet(viewModel: viewModel)
        }
    }
    
    // MARK: - Header Section
    private var headerSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Lum1na")
                    .font(.system(.largeTitle, weight: .bold, design: .rounded))
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
                    
                    Text(viewModel.exploitState.description)
                        .font(.system(.subheadline, weight: .medium))
                        .foregroundColor(statusColor)
                }
            }
            
            Spacer()
            
            // Device Info Button
            Button(action: { showingAllExploits = true }) {
                Image(systemName: "info.circle")
                    .font(.title3)
                    .foregroundColor(.lum1naCyan)
            }
        }
        .padding(.horizontal, 20)
        .padding(.top, 20)
    }
    
    // MARK: - Liquid Bubbles Section
    private var liquidBubblesSection: some View {
        HStack(spacing: 20) {
            ForEach(0..<3) { index in
                LiquidBubbleView(
                    motion: bubbleMotion,
                    color: currentStage.color,
                    delay: Double(index) * 0.3
                )
            }
        }
    }
    
    // MARK: - Full Chain Button
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
            .shadow(color: currentStage.glowColor.opacity(viewModel.isRunning ? 0 : 0.3), radius: 8)
        }
        .disabled(viewModel.isRunning)
    }
    
    // MARK: - All Exploits Button
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
    
    // MARK: - Status Color Helper
    private var statusColor: Color {
        switch viewModel.exploitState {
        case .success: return .consoleSuccess
        case .failed: return .consoleError
        case .idle: return .gray
        default: return currentStage.color
        }
    }
}

// MARK: - Liquid Bubble View
struct LiquidBubbleView: View {
    @ObservedObject var motion: LiquidBubbleMotionState
    let color: Color
    let delay: Double
    
    @State private var isAnimating = false
    
    var body: some View {
        Circle()
            .fill(
                RadialGradient(
                    colors: [
                        color.opacity(0.4),
                        color.opacity(0.1),
                        .clear
                    ],
                    center: .center,
                    startRadius: 5,
                    endRadius: 20
                )
            )
            .frame(width: 40, height: 40)
            .scaleEffect(isAnimating ? 1.2 : 0.8)
            .opacity(isAnimating ? 0.6 : 0.3)
            .offset(motion.offset)
            .gesture(
                DragGesture()
                    .onChanged { value in
                        motion.updateDrag(translation: value.translation)
                    }
                    .onEnded { _ in
                        motion.endDrag()
                    }
            )
            .onAppear {
                withAnimation(
                    .easeInOut(duration: 2)
                    .repeatForever(autoreverses: true)
                    .delay(delay)
                ) {
                    isAnimating = true
                }
            }
    }
}

// MARK: - All Exploits Sheet
struct AllExploitsSheet: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @Environment(\.dismiss) var dismiss
    
    let exploits = [
        ("P044 ANE 254-Input", "KERNEL", "brain", Color.badgeKernel),
        ("CVE-2026-65343 AKS", "SANDBOX", "lock.shield", Color.badgeSandbox),
        ("P035 AVE Wrap", "KERNEL", "video", Color.lum1naViolet),
        ("P051 APFS Xattr", "SANDBOX", "folder", Color.badgeSandbox),
        ("P054 APFS Reap", "DAEMON", "archivebox", Color.badgeDaemon),
    ]
    
    var body: some View {
        NavigationView {
            List {
                Section(header: Text("EXPLOIT CHAIN")) {
                    ForEach(exploits, id: \.0) { exploit in
                        Button {
                            Task {
                                await viewModel.executeStage(exploit.1)
                                dismiss()
                            }
                        } label: {
                            HStack {
                                Image(systemName: exploit.2)
                                    .foregroundColor(exploit.3)
                                    .frame(width: 24)
                                
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(exploit.0)
                                        .font(.system(.subheadline, weight: .semibold))
                                        .foregroundColor(.primary)
                                    
                                    Text(exploit.1)
                                        .font(.system(.caption, design: .rounded))
                                        .foregroundColor(exploit.3.opacity(0.8))
                                }
                                
                                Spacer()
                                
                                Image(systemName: "chevron.right")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                        .disabled(viewModel.isRunning)
                    }
                }
                
                Section(header: Text("DEBUG")) {
                    Button {
                        UIPasteboard.general.string = viewModel.exportFullDebugLog()
                        dismiss()
                    } label: {
                        Label("Export Full Log", systemImage: "doc.on.clipboard")
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
                
                Section(header: Text("DEVICE INFO")) {
                    LabeledContent("Machine", value: viewModel.deviceInfo?.machine ?? "Unknown")
                    LabeledContent("iOS Version", value: viewModel.deviceInfo?.version ?? "Unknown")
                    LabeledContent("Kernel Slide", value: viewModel.currentKernelSlide != 0 
                        ? "0x\(String(viewModel.currentKernelSlide, radix: 16, uppercase: true))"
                        : "Not obtained")
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

// MARK: - Preview
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
            .preferredColorScheme(.dark)
    }
}

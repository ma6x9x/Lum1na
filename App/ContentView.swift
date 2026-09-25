//
//  ContentView.swift
//  Lum1na
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = ExploitManager.shared
    @State private var showingAllExploits = false
    @State private var selectedStage: ExploitStage?

    var body: some View {
        ZStack {
            CircuitBackgroundView(stage: currentStage)
                .ignoresSafeArea()

            GlyphRainView(intensity: 0.3)
                .opacity(0.3)

            VStack(spacing: 0) {
                headerSection
                    .padding(.top, 20)

                StarBeaconView(stage: currentStage)
                    .frame(height: 120)
                    .padding(.vertical, 10)

                HStack(spacing: 16) {
                    ForEach([BadgeType.kernel, .sandbox, .daemon, .patchset], id: \.self) { badge in
                        HexagonBadgeView(
                            type: badge,
                            isActive: activeBadges.contains(badge)
                        )
                    }
                }
                .padding(.vertical, 8)

                CentralHeapView(
                    heapAddress: viewModel.currentKernelSlide != 0
                        ? "0x\(String(viewModel.currentKernelSlide, radix: 16, uppercase: true))"
                        : nil,
                    stage: currentStage
                )
                .padding(.vertical, 8)

                HStack(spacing: 20) {
                    ForEach(0..<3) { index in
                        LiquidBubbleView(
                            color: currentStage.color,
                            delay: Double(index) * 0.3
                        )
                    }
                }
                .frame(height: 60)

                MatrixConsoleView()
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)

                Spacer(minLength: 10)

                ExploitStageSelector(
                    selectedStage: $selectedStage,
                    isRunning: $viewModel.isRunning,
                    onStageSelected: { stage in
                        Task { await viewModel.executeStage(stage.rawValue) }
                    }
                )
                .padding(.horizontal, 16)

                fullChainButton
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)

                allExploitsButton
                    .padding(.bottom, 20)
            }

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

    private var activeBadges: Set<BadgeType> {
        var badges: Set<BadgeType> = []
        guard let stage = viewModel.selectedStage else { return badges }

        badges.insert(.kernel)
        if stage == .sandbox || stage == .daemon || stage == .patchset {
            badges.insert(.sandbox)
        }
        if stage == .daemon || stage == .patchset {
            badges.insert(.daemon)
        }
        if stage == .patchset {
            badges.insert(.patchset)
        }
        return badges
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

            Button(action: { showingAllExploits = true }) {
                Image(systemName: "info.circle")
                    .font(.title3)
                    .foregroundColor(.lum1naCyan)
            }
        }
        .padding(.horizontal, 20)
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
            .shadow(color: currentStage.glowColor.opacity(viewModel.isRunning ? 0 : 0.3), radius: 8)
        }
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

    private var statusColor: Color {
        if viewModel.lastResult.isSuccess { return .consoleSuccess }
        return viewModel.isRunning ? currentStage.color : .gray
    }
}

struct LiquidBubbleView: View {
    let color: Color
    let delay: Double
    @State private var isAnimating = false
    @State private var dragOffset: CGSize = .zero

    var body: some View {
        Circle()
            .fill(
                RadialGradient(
                    colors: [color.opacity(0.4), color.opacity(0.1), .clear],
                    center: .center,
                    startRadius: 5,
                    endRadius: 20
                )
            )
            .frame(width: 40, height: 40)
            .scaleEffect(isAnimating ? 1.2 : 0.8)
            .opacity(isAnimating ? 0.6 : 0.3)
            .offset(dragOffset)
            .gesture(
                DragGesture()
                    .onChanged { value in dragOffset = value.translation }
                    .onEnded { _ in withAnimation(.spring()) { dragOffset = .zero } }
            )
            .onAppear {
                withAnimation(.easeInOut(duration: 2).repeatForever(autoreverses: true).delay(delay)) {
                    isAnimating = true
                }
            }
    }
}

struct AllExploitsSheet: View {
    @ObservedObject var viewModel: ExploitManager
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
                    LabeledContent("Machine", value: DeviceUtils.currentDevice)
                    LabeledContent("Category", value: DeviceUtils.deviceCategory)
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

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
            .preferredColorScheme(.dark)
    }
}

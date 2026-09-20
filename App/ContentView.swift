import SwiftUI
import UIKit

enum ExploitStage: String, CaseIterable, Identifiable {
    case kaslr = "KASLR"
    case uaf = "Heap"
    case ane = "ANE"
    case ppl = "PPL"
    case persist = "Persist"
    case fullChain = "Full Chain"

    var id: String { rawValue }

    var detailTitle: String {
        switch self {
        case .kaslr: return "KASLR Leak"
        case .uaf: return "Heap Corruption"
        case .ane: return "ANE OOB Write"
        case .ppl: return "PPL Bypass"
        case .persist: return "Persistence"
        case .fullChain: return "Full Chain"
        }
    }
}

struct ContentView: View {
    @StateObject private var manager = ExploitManager.shared
    @State private var showStages = false

    private let individualStages: [ExploitStage] = [.kaslr, .uaf, .ane, .ppl, .persist]

    var body: some View {
        ZStack {
            Lum1naPalette.field.ignoresSafeArea()
            GlyphRainView(intensity: manager.isRunning ? 1.25 : 0.7)

            VStack(spacing: 0) {
                header
                    .padding(.top, 10)

                Spacer(minLength: 6)

                StarBeaconView(isActive: manager.isRunning)
                    .padding(.vertical, 4)

                Text("The guiding light for Jailbreaks")
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(Lum1naPalette.ice.opacity(0.92))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
                    .padding(.top, 6)

                Spacer(minLength: 10)

                MatrixConsoleView()
                    .frame(maxHeight: 200)
                    .padding(.horizontal, 16)

                Spacer(minLength: 10)

                chrome
                    .padding(.horizontal, 16)
                    .padding(.bottom, 18)
            }
        }
    }

    private var header: some View {
        ZStack {
            HStack(spacing: 28) {
                cloudWisp.offset(x: -6, y: 10)
                Spacer()
                cloudWisp.offset(x: 6, y: 6)
            }
            .padding(.horizontal, 28)
            .opacity(0.55)

            VStack(spacing: 6) {
                Text("Lum1na")
                    .font(.system(size: 36, weight: .bold, design: .rounded))
                    .foregroundStyle(Lum1naPalette.wordmarkGradient)
                    .shadow(color: Lum1naPalette.magenta.opacity(0.35), radius: 10)

                Text("v0.1 · private beta")
                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.45))
            }
        }
    }

    private var cloudWisp: some View {
        Capsule()
            .fill(
                LinearGradient(
                    colors: [Color.white.opacity(0.14), Color.white.opacity(0.04)],
                    startPoint: .leading,
                    endPoint: .trailing
                )
            )
            .frame(width: 72, height: 18)
            .blur(radius: 6)
    }

    private var chrome: some View {
        VStack(spacing: 12) {
            deviceCard

            if showStages {
                stageRow
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }

            HStack(spacing: 10) {
                Button {
                    withAnimation(.spring(response: 0.35, dampingFraction: 0.86)) {
                        showStages.toggle()
                    }
                } label: {
                    Text(showStages ? "Hide stages" : "Test stages")
                }
                .buttonStyle(LiquidGlassCapsuleButtonStyle(prominent: false))
                .disabled(manager.isRunning)

                Button {
                    manager.runExploit(.fullChain)
                } label: {
                    Text(manager.isRunning && manager.selectedStage == .fullChain ? "Running…" : "Jailbreak")
                }
                .buttonStyle(LiquidGlassCapsuleButtonStyle(prominent: true))
                .disabled(manager.isRunning)
            }

            statusRow
        }
    }

    private var deviceCard: some View {
        LiquidGlassCard(cornerRadius: 18) {
            HStack(spacing: 12) {
                Image(systemName: "iphone")
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(Lum1naPalette.violet)
                    .frame(width: 40, height: 40)
                    .background(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(Lum1naPalette.violet.opacity(0.18))
                    )

                VStack(alignment: .leading, spacing: 2) {
                    Text(deviceTitle)
                        .font(.system(size: 15, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white)
                    Text(osSubtitle)
                        .font(.system(size: 12, weight: .medium, design: .rounded))
                        .foregroundStyle(.white.opacity(0.55))
                }
                Spacer(minLength: 0)
                Circle()
                    .fill(manager.isRunning ? Color.green : Lum1naPalette.ice.opacity(0.7))
                    .frame(width: 8, height: 8)
                    .shadow(
                        color: (manager.isRunning ? Color.green : Lum1naPalette.ice).opacity(0.7),
                        radius: 4
                    )
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
        }
    }

    private var stageRow: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(individualStages) { stage in
                    Button {
                        manager.runExploit(stage)
                    } label: {
                        Text(stage.rawValue)
                            .font(.system(size: 13, weight: .semibold, design: .rounded))
                            .padding(.horizontal, 14)
                            .padding(.vertical, 10)
                            .foregroundStyle(.white)
                            .background {
                                Capsule(style: .continuous)
                                    .fill(.ultraThinMaterial)
                                    .overlay {
                                        Capsule(style: .continuous)
                                            .fill(
                                                LinearGradient(
                                                    colors: [Color.white.opacity(0.14), Color.clear],
                                                    startPoint: .top,
                                                    endPoint: .center
                                                )
                                            )
                                    }
                            }
                            .overlay {
                                Capsule(style: .continuous)
                                    .strokeBorder(
                                        manager.selectedStage == stage
                                            ? Lum1naPalette.magenta.opacity(0.9)
                                            : Color.white.opacity(0.16),
                                        lineWidth: 1
                                    )
                            }
                    }
                    .buttonStyle(.plain)
                    .disabled(manager.isRunning)
                    .opacity(manager.isRunning && manager.selectedStage != stage ? 0.4 : 1)
                    .accessibilityLabel(stage.detailTitle)
                }
            }
            .padding(.vertical, 2)
        }
    }

    private var statusRow: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(manager.isRunning ? Color.green : Color.gray.opacity(0.65))
                .frame(width: 7, height: 7)
            Text(statusText)
                .font(.system(size: 12, weight: .medium, design: .rounded))
                .foregroundStyle(manager.isRunning ? Color.green : Color.white.opacity(0.55))
            Spacer()
            Text("\(manager.lines.count) lines")
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.white.opacity(0.35))
        }
        .padding(.horizontal, 4)
    }

    private var statusText: String {
        if manager.isRunning, let stage = manager.selectedStage {
            return "Running · \(stage.detailTitle)"
        }
        return "Ready"
    }

    private var deviceTitle: String {
        UIDevice.current.model
    }

    private var osSubtitle: String {
        "iOS \(UIDevice.current.systemVersion)"
    }
}

#Preview {
    ContentView()
}

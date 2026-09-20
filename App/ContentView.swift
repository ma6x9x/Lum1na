import SwiftUI

enum ExploitStage: String, CaseIterable, Identifiable {
    case kaslr = "KASLR Leak"
    case uaf = "Heap Corruption"
    case ane = "ANE OOB Write"
    case ppl = "PPL Bypass"
    case persist = "Persistence"
    case fullChain = "Full Chain"

    var id: String { rawValue }
}

struct StageButton: View {
    let stage: ExploitStage
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(stage.rawValue)
                .font(.system(size: 14, weight: .semibold, design: .rounded))
                .padding(.horizontal, 18)
                .padding(.vertical, 11)
                .background(background)
                .foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .stroke(Color.white.opacity(isSelected ? 0.35 : 0.14), lineWidth: 1)
                )
                .shadow(color: isSelected ? Color.purple.opacity(0.45) : .clear, radius: 10, y: 2)
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private var background: some View {
        if isSelected {
            LinearGradient(
                colors: [Color.purple, Color.blue.opacity(0.95)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        } else {
            Color.white.opacity(0.1)
        }
    }
}

struct ContentView: View {
    @StateObject private var manager = ExploitManager.shared

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color.black,
                    Color(red: 0.12, green: 0.04, blue: 0.2),
                    Color.black
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            VStack(spacing: 22) {
                header

                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        ForEach(ExploitStage.allCases) { stage in
                            StageButton(
                                stage: stage,
                                isSelected: manager.selectedStage == stage,
                                action: { manager.runExploit(stage) }
                            )
                            .disabled(manager.isRunning)
                            .opacity(manager.isRunning && manager.selectedStage != stage ? 0.45 : 1)
                        }
                    }
                    .padding(.horizontal, 4)
                }

                MatrixConsoleView()
                    .frame(maxHeight: 320)
                    .padding(.horizontal, 2)

                statusRow
            }
            .padding(.vertical, 20)
            .padding(.horizontal, 16)
        }
    }

    private var header: some View {
        VStack(spacing: 10) {
            Image(systemName: "sparkle")
                .resizable()
                .scaledToFit()
                .frame(width: 64, height: 64)
                .foregroundStyle(
                    LinearGradient(
                        colors: [.purple, .cyan.opacity(0.9)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .shadow(color: .purple.opacity(0.7), radius: 14)
                .rotationEffect(.degrees(manager.logoAnimation ? 360 : 0))
                .onAppear {
                    withAnimation(.linear(duration: 10).repeatForever(autoreverses: false)) {
                        manager.logoAnimation = true
                    }
                }

            Text("Lum1na")
                .font(.system(size: 34, weight: .bold, design: .rounded))
                .foregroundStyle(.white)
                .shadow(color: .purple.opacity(0.45), radius: 8)

            Text("Private developer build")
                .font(.system(size: 12, weight: .medium, design: .rounded))
                .foregroundStyle(.white.opacity(0.55))
        }
    }

    private var statusRow: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(manager.isRunning ? Color.green : Color.gray.opacity(0.7))
                .frame(width: 8, height: 8)
                .shadow(color: manager.isRunning ? .green.opacity(0.8) : .clear, radius: 4)

            Text(manager.isRunning ? "Running…" : "Ready")
                .font(.caption.weight(.medium))
                .foregroundStyle(manager.isRunning ? Color.green : Color.gray)

            Spacer(minLength: 0)

            Text("\(manager.lines.count) lines")
                .font(.caption2.monospaced())
                .foregroundStyle(.white.opacity(0.35))
        }
        .padding(.horizontal, 4)
        .padding(.top, 4)
    }
}

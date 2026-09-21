import SwiftUI

// PASTE SLOT: overwrite this file with your other agent's ContentView.swift
// (stubs below match that API so the project compiles before you paste)

struct ContentView: View {
    @StateObject private var manager = ExploitManager.shared

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color.black, Color.purple.opacity(0.2), Color.black],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            VStack(spacing: 24) {
                Image(systemName: "star.fill")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 80, height: 80)
                    .foregroundColor(.purple)
                    .shadow(color: .purple.opacity(0.8), radius: 10)
                    .rotationEffect(.degrees(manager.logoAnimation ? 360 : 0))
                    .onAppear {
                        withAnimation(.linear(duration: 8).repeatForever(autoreverses: false)) {
                            manager.logoAnimation = true
                        }
                    }

                Text("Lum1na")
                    .font(.system(size: 36, weight: .bold, design: .rounded))
                    .foregroundColor(.white)
                    .shadow(color: .purple.opacity(0.5), radius: 10)

                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 12) {
                        ForEach(ExploitStage.allCases, id: \.self) { stage in
                            StageButton(
                                stage: stage,
                                isSelected: manager.selectedStage == stage,
                                action: { manager.runExploit(stage) }
                            )
                            .disabled(manager.isRunning)
                        }
                    }
                    .padding(.horizontal)
                }

                MatrixConsoleView()
                    .frame(height: 300)

                HStack(spacing: 8) {
                    Circle()
                        .fill(manager.isRunning ? Color.green : Color.gray)
                        .frame(width: 8, height: 8)
                    Text(manager.isRunning ? "Exploiting..." : "Ready")
                        .font(.caption)
                        .foregroundColor(manager.isRunning ? .green : .gray)
                }
                .padding(.top, 8)
            }
            .padding()
        }
    }
}

struct StageButton: View {
    let stage: ExploitStage
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(stage.rawValue)
                .font(.system(size: 14, weight: .medium, design: .rounded))
                .padding(.horizontal, 20)
                .padding(.vertical, 12)
                .background(backgroundView)
                .foregroundColor(.white)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.white.opacity(0.2), lineWidth: 1)
                )
                .shadow(color: isSelected ? Color.purple.opacity(0.5) : Color.clear, radius: 8)
        }
    }

    @ViewBuilder
    private var backgroundView: some View {
        if isSelected {
            LinearGradient(colors: [Color.purple, Color.blue], startPoint: .leading, endPoint: .trailing)
        } else {
            Color.white.opacity(0.1)
        }
    }
}

#Preview {
    ContentView()
}

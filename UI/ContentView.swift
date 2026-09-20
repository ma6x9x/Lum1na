import SwiftUI

enum ExploitStage: String, CaseIterable {
    case kaslr = "KASLR Leak"
    case uaf = "Heap Corruption"
    case ane = "ANE OOB Write"
    case ppl = "PPL Bypass"
    case persist = "Persistence"
    case fullChain = "Full Chain"
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
                .background(self.backgroundColor)
                .foregroundColor(.white)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.white.opacity(0.2), lineWidth: 1)
                )
                .shadow(color: self.shadowColor, radius: 8)
        }
    }
    
    private var backgroundColor: AnyView {
        if isSelected {
            return AnyView(LinearGradient(colors: [Color.purple, Color.blue], startPoint: .leading, endPoint: .trailing))
        } else {
            return AnyView(Color.white.opacity(0.1))
        }
    }
    
    private var shadowColor: Color {
        return isSelected ? Color.purple.opacity(0.5) : Color.clear
    }
}

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
                                action: {
                                    manager.runExploit(stage)
                                }
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
                        .shadow(color: manager.isRunning ? .green.opacity(0.8) : .clear, radius: 4)
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

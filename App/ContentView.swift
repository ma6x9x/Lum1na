import SwiftUI

struct ContentView: View {
    @State private var currentStage: JailbreakStage = .idle
    @State private var selectedExploitStage: ExploitChainStage? = nil
    @State private var isJailbreaking = false
    @State private var heapAddress: String? = nil
    @State private var activeBadges: Set<BadgeType> = []
    @State private var showSuccess = false
    @State private var consoleView = MatrixConsoleView()
    
    var body: some View {
        ZStack {
            CircuitBackgroundView(stage: currentStage)
                .ignoresSafeArea()
            
            VStack(spacing: 0) {
                headerView
                    .padding(.top, 16)
                
                Spacer(minLength: 10)
                
                reactorView
                    .padding(.vertical, 10)
                
                Spacer(minLength: 10)
                
                ExploitStageSelector(
                    selectedStage: $selectedExploitStage,
                    isRunning: $isJailbreaking,
                    onStageSelected: { stage in
                        handleStageSelected(stage)
                    }
                )
                .padding(.horizontal, 16)
                .padding(.bottom, 12)
                
                BadgeContainerView(activeBadges: activeBadges, stage: currentStage)
                    .padding(.bottom, 12)
                
                consoleView
                    .padding(.horizontal, 16)
                    .padding(.bottom, 12)
                
                buttonBar
                    .padding(.horizontal, 16)
                    .padding(.bottom, 24)
            }
        }
        .alert("Jailbreak Complete", isPresented: $showSuccess) {
            Button("OK") { }
        } message: {
            Text("Your device has been successfully jailbroken.")
        }
    }
    
    private var headerView: some View {
        VStack(spacing: 4) {
            Text("Lum1na")
                .font(.system(size: 32, weight: .bold, design: .rounded))
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color(hex: "#8B5CF6"), Color(hex: "#06B6D4")],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
            
            HStack(spacing: 8) {
                Text("Beta 1")
                    .font(.system(.caption, weight: .medium))
                    .foregroundStyle(Color(hex: "#64748B"))
                
                Text("•")
                    .font(.system(.caption))
                    .foregroundStyle(Color(hex: "#334155"))
                
                Text("iPhone15,2")
                    .font(.system(.caption, weight: .medium, design: .monospaced))
                    .foregroundStyle(Color(hex: "#64748B"))
            }
        }
    }
    
    private var reactorView: some View {
        ZStack {
            Circle()
                .fill(
                    RadialGradient(
                        colors: [
                            currentStage.color.opacity(0.2),
                            currentStage.color.opacity(0.05),
                            .clear
                        ],
                        center: .center,
                        startRadius: 0,
                        endRadius: 140
                    )
                )
                .frame(width: 280, height: 280)
                .blur(radius: 20)
            
            CentralHeapView(heapAddress: heapAddress, stage: currentStage)
                .offset(y: 35)
            
            StarBeaconView(stage: currentStage)
                .offset(y: -25)
            
            VStack {
                Spacer()
                Text(currentStage.rawValue)
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                    .foregroundStyle(currentStage.color)
                    .shadow(color: currentStage.color.opacity(0.5), radius: 6)
                    .padding(.top, 90)
            }
        }
        .frame(height: 220)
    }
    
    private var buttonBar: some View {
        HStack(spacing: 12) {
            Button {
                if isJailbreaking {
                    stopJailbreak()
                } else {
                    startJailbreak()
                }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: isJailbreaking ? "stop.fill" : "power")
                        .font(.system(size: 14, weight: .semibold))
                    Text(isJailbreaking ? "STOP" : "HOLD")
                        .font(.system(.subheadline, weight: .semibold))
                }
                .foregroundStyle(isJailbreaking ? Color(hex: "#EF4444") : Color.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(
                    Capsule()
                        .fill(isJailbreaking ? Color(hex: "#EF4444").opacity(0.15) : Color(hex: "#8B5CF6").opacity(0.2))
                        .overlay(
                            Capsule()
                                .stroke(isJailbreaking ? Color(hex: "#EF4444").opacity(0.5) : Color(hex: "#8B5CF6").opacity(0.5), lineWidth: 1.5)
                        )
                )
            }
            
            Button { } label: {
                HStack(spacing: 6) {
                    Image(systemName: isJailbreaking ? "hourglass" : "checkmark.shield")
                        .font(.system(size: 14))
                    Text(isJailbreaking ? "WORKING" : "READY")
                        .font(.system(.subheadline, weight: .semibold))
                }
                .foregroundStyle(isJailbreaking ? Color(hex: "#F59E0B") : Color(hex: "#10B981"))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(
                    Capsule()
                        .fill(Color.white.opacity(0.05))
                        .overlay(Capsule().stroke(Color.white.opacity(0.15), lineWidth: 1))
                )
            }
            .disabled(true)
        }
    }
    
    private func handleStageSelected(_ stage: ExploitChainStage) {
        consoleView.addLog(level: mapStageToLogLevel(stage), message: "Selected stage: \(stage.displayName)")
    }
    
    private func startJailbreak() {
        isJailbreaking = true
        let stages: [(JailbreakStage, ExploitChainStage?, BadgeType?, String)] = [
            (.kaslr, .kernel, .kernel, "KASLR bypass initiated"),
            (.heap, .sandbox, .sandbox, "Sandbox escape: 0x00006085427A"),
            (.ane, .daemon, .daemon, "ANE daemon compromised"),
            (.ppl, .patchset, .patchset, "PPL bypass complete"),
            (.persist, nil, nil, "Persistence installed")
        ]
        
        var delay: TimeInterval = 0
        for (jbStage, exploitStage, badge, logMessage) in stages {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                guard self.isJailbreaking else { return }
                withAnimation(.easeInOut(duration: 0.4)) {
                    self.currentStage = jbStage
                    if let es = exploitStage { self.selectedExploitStage = es }
                }
                if let b = badge { self.activeBadges.insert(b) }
                if jbStage == .heap { self.heapAddress = "0x00006085427A" }
                
                let logLevel: CategorizedLogLevel = {
                    switch jbStage {
                    case .kaslr: return .kernel
                    case .heap: return .sandbox
                    case .ane: return .daemon
                    case .ppl: return .patchset
                    case .persist: return .success
                    default: return .init_
                    }
                }()
                consoleView.addLog(level: logLevel, message: logMessage)
            }
            delay += 1.5
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            guard self.isJailbreaking else { return }
            self.isJailbreaking = false
            self.showSuccess = true
            consoleView.addLog(level: .success, message: "Jailbreak complete!")
        }
    }
    
    private func stopJailbreak() {
        isJailbreaking = false
        currentStage = .idle
        heapAddress = nil
        activeBadges.removeAll()
        selectedExploitStage = nil
        consoleView.addLog(level: .error, message: "Jailbreak stopped by user")
    }
    
    private func mapStageToLogLevel(_ stage: ExploitChainStage) -> CategorizedLogLevel {
        switch stage {
        case .kernel: return .kernel
        case .sandbox: return .sandbox
        case .daemon: return .daemon
        case .patchset: return .patchset
        }
    }
}

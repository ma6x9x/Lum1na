import SwiftUI

struct ContentView: View {
    @State private var currentStage: JailbreakStage = .idle
    @State private var isJailbreaking = false
    @State private var heapAddress: String? = nil
    @State private var activeBadges: Set<BadgeType> = []
    @State private var console = ConsoleViewModel()
    @State private var showSuccess = false
    
    var body: some View {
        ZStack {
            Color.lum1naField.ignoresSafeArea()
            CircuitBackgroundView(stage: currentStage).ignoresSafeArea().opacity(0.6)
            
            VStack(spacing: 0) {
                headerView
                Spacer()
                reactorView.padding(.vertical, 20)
                Spacer()
                BadgeContainerView(activeBadges: activeBadges, stage: currentStage).padding(.bottom, 16)
                MatrixConsoleView().padding(.horizontal, 16).padding(.bottom, 16)
                buttonBar.padding(.horizontal, 16).padding(.bottom, 24)
            }
        }
        .alert("Jailbreak Complete", isPresented: $showSuccess) {
            Button("OK") { }
        } message: { Text("Your device has been successfully jailbroken.") }
    }
    
    private var headerView: some View {
        VStack(spacing: 4) {
            Text("Lum1na").font(.system(.largeTitle, weight: .bold, design: .rounded))
                .foregroundStyle(LinearGradient(colors: [.lum1naViolet, .lum1naCyan], startPoint: .leading, endPoint: .trailing))
            Text("Beta 1").font(.system(.caption, weight: .medium)).foregroundStyle(.consoleTimestamp)
        }.padding(.top, 20)
    }
    
    private var reactorView: some View {
        ZStack {
            Circle().fill(RadialGradient(colors: [currentStage.color.opacity(0.3), currentStage.color.opacity(0.1), .clear], center: .center, startRadius: 0, endRadius: 150)).frame(width: 300, height: 300).blur(radius: 30)
            CentralHeapView(heapAddress: heapAddress, stage: currentStage).offset(y: 40)
            StarBeaconView(stage: currentStage).offset(y: -20)
            VStack {
                Spacer()
                Text(currentStage.rawValue).font(.system(.title3, weight: .semibold, design: .rounded)).foregroundStyle(currentStage.color).shadow(color: currentStage.glowColor, radius: 8).padding(.top, 100)
            }
        }.frame(height: 280)
    }
    
    private var buttonBar: some View {
        HStack(spacing: 12) {
            Button { if isJailbreaking { stopJailbreak() } else { startJailbreak() } } label: {
                HStack(spacing: 6) {
                    Image(systemName: isJailbreaking ? "stop.fill" : "power")
                    Text(isJailbreaking ? "STOP" : "HOLD")
                }.font(.buttonLabel).foregroundStyle(isJailbreaking ? .lum1naPink : .white).frame(maxWidth: .infinity).padding(.vertical, 14)
                .background(Capsule().fill(isJailbreaking ? Color.lum1naPink.opacity(0.15) : Color.lum1naViolet.opacity(0.15)).overlay(Capsule().stroke(isJailbreaking ? Color.lum1naPink.opacity(0.5) : Color.white.opacity(0.2), lineWidth: 1)))
            }
            Button { } label: {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.shield")
                    Text(isJailbreaking ? "WORKING" : "READY")
                }.font(.buttonLabel).foregroundStyle(isJailbreaking ? .lum1naCyan : .consoleSuccess).frame(maxWidth: .infinity).padding(.vertical, 14)
                .background(Capsule().fill(Color.white.opacity(0.05)).overlay(Capsule().stroke(Color.white.opacity(0.15), lineWidth: 1)))
            }.disabled(isJailbreaking)
        }
    }
    
    private func startJailbreak() {
        isJailbreaking = true
        console.info("Starting jailbreak sequence...")
        let stages: [JailbreakStage] = [.kaslr, .heap, .ane, .ppl, .persist]
        var delay: TimeInterval = 0
        for stage in stages {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                guard self.isJailbreaking else { return }
                self.advanceToStage(stage)
            }
            delay += 2.0
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            guard self.isJailbreaking else { return }
            self.completeJailbreak()
        }
    }
    
    private func stopJailbreak() {
        isJailbreaking = false
        currentStage = .idle
        heapAddress = nil
        activeBadges.removeAll()
        console.warning("Jailbreak sequence aborted by user")
    }
    
    private func advanceToStage(_ stage: JailbreakStage) {
        withAnimation(.easeInOut(duration: 0.5)) { currentStage = stage }
        switch stage {
        case .kaslr: console.info("Bypassing KASLR..."); activeBadges.insert(.kernel)
        case .heap: console.info("Spraying heap..."); heapAddress = String(format: "0x%012X", Int.random(in: 0x100000000000...0x1FFFFFFFFFFF)); activeBadges.insert(.sandbox)
        case .ane: console.info("Initializing ANE context..."); activeBadges.insert(.daemon)
        case .ppl: console.info("Bypassing PPL..."); activeBadges.insert(.patchset)
        case .persist: console.success("Installing persistence...")
        default: break
        }
    }
    
    private func completeJailbreak() {
        isJailbreaking = false
        console.success("Jailbreak completed successfully!")
        showSuccess = true
    }
}

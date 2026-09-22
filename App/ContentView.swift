import SwiftUI

struct ContentView: View {
    @State private var currentStage: ExploitStage = .idle
    @State private var isJailbreaking = false
    @State private var heapAddress: String? = nil
    @State private var activeBadges: Set<BadgeType> = []
    @State private var showSuccess = false
    
    var body: some View {
        ZStack {
            Color(hex: "#07060F").ignoresSafeArea()
            
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
            Text("Lum1na")
                .font(.system(size: 34, weight: .bold, design: .rounded))
                .foregroundStyle(LinearGradient(colors: [Color(hex: "#8B5CF6"), Color(hex: "#06B6D4")], startPoint: .leading, endPoint: .trailing))
            Text("Beta 1").font(.system(.caption, weight: .medium)).foregroundStyle(Color(hex: "#64748B"))
        }.padding(.top, 20)
    }
    
    private var reactorView: some View {
        ZStack {
            Circle().fill(RadialGradient(colors: [currentStage.color.opacity(0.3), currentStage.color.opacity(0.1), .clear], center: .center, startRadius: 0, endRadius: 150)).frame(width: 300, height: 300).blur(radius: 30)
            CentralHeapView(heapAddress: heapAddress, stage: currentStage).offset(y: 40)
            StarBeaconView(stage: currentStage).offset(y: -20)
            VStack {
                Spacer()
                Text(currentStage.rawValue)
                    .font(.system(size: 20, weight: .semibold, design: .rounded))
                    .foregroundStyle(currentStage.color)
                    .shadow(color: currentStage.color.opacity(0.6), radius: 8)
                    .padding(.top, 100)
            }
        }.frame(height: 280)
    }
    
    private var buttonBar: some View {
        HStack(spacing: 12) {
            Button {
                if isJailbreaking { stopJailbreak() } else { startJailbreak() }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: isJailbreaking ? "stop.fill" : "power")
                    Text(isJailbreaking ? "STOP" : "HOLD")
                }
                .font(.system(.subheadline, weight: .medium))
                .foregroundStyle(isJailbreaking ? Color(hex: "#EC4899") : Color.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(Capsule().fill(isJailbreaking ? Color(hex: "#EC4899").opacity(0.15) : Color(hex: "#8B5CF6").opacity(0.15)).overlay(Capsule().stroke(isJailbreaking ? Color(hex: "#EC4899").opacity(0.5) : Color.white.opacity(0.2), lineWidth: 1)))
            }
            
            Button { } label: {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.shield")
                    Text(isJailbreaking ? "WORKING" : "READY")
                }
                .font(.system(.subheadline, weight: .medium))
                .foregroundStyle(isJailbreaking ? Color(hex: "#06B6D4") : Color(hex: "#4ADE80"))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(Capsule().fill(Color.white.opacity(0.05)).overlay(Capsule().stroke(Color.white.opacity(0.15), lineWidth: 1)))
            }.disabled(isJailbreaking)
        }
    }
    
    private func startJailbreak() {
        isJailbreaking = true
        let stages: [JailbreakStage] = [.kaslr, .heap, .ane, .ppl, .persist]
        var delay: TimeInterval = 0
        for stage in stages {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                guard self.isJailbreaking else { return }
                withAnimation(.easeInOut(duration: 0.5)) { self.currentStage = stage }
                switch stage {
                case .kaslr: self.activeBadges.insert(.kernel)
                case .heap: self.heapAddress = String(format: "0x%012X", Int.random(in: 0x100000000000...0x1FFFFFFFFFFF)); self.activeBadges.insert(.sandbox)
                case .ane: self.activeBadges.insert(.daemon)
                case .ppl: self.activeBadges.insert(.patchset)
                default: break
                }
            }
            delay += 2.0
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            guard self.isJailbreaking else { return }
            self.isJailbreaking = false
            self.showSuccess = true
        }
    }
    
    private func stopJailbreak() {
        isJailbreaking = false
        currentStage = .idle
        heapAddress = nil
        activeBadges.removeAll()
    }
}

// Supporting types
enum JailbreakStage: String {
    case idle = "IDLE"
    case kaslr = "KASLR"
    case heap = "HEAP"
    case ane = "ANE"
    case ppl = "PPL"
    case persist = "PERSIST"
    
    var color: Color {
        switch self {
        case .idle: return Color(hex: "#8B5CF6")
        case .kaslr: return Color(hex: "#06B6D4")
        case .heap: return Color(hex: "#A855F7")
        case .ane: return Color(hex: "#3B82F6")
        case .ppl: return Color(hex: "#D946EF")
        case .persist: return Color(hex: "#EC4899")
        }
    }
}

enum BadgeType: String, CaseIterable {
    case kernel = "KERNEL"
    case sandbox = "SANDBOX"
    case daemon = "DAEMON"
    case patchset = "PATCHSET"
}

extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3: (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default: (a, r, g, b) = (1, 1, 1, 0)
        }
        self.init(.sRGB, red: Double(r) / 255, green: Double(g) / 255, blue: Double(b) / 255, opacity: Double(a) / 255)
    }
}

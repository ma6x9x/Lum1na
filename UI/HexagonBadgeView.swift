import SwiftUI

enum BadgeType: String, CaseIterable {
    case kernel = "KERNEL"
    case sandbox = "SANDBOX"
    case daemon = "DAEMON"
    case patchset = "PATCHSET"
    
    var color: Color {
        switch self {
        case .kernel:   return Color(hex: "#EF4444")
        case .sandbox:  return Color(hex: "#F59E0B")
        case .daemon:   return Color(hex: "#10B981")
        case .patchset: return Color(hex: "#3B82F6")
        }
    }
    
    var icon: String {
        switch self {
        case .kernel:   return "cpu"
        case .sandbox:  return "lock.shield"
        case .daemon:   return "gearshape.2"
        case .patchset: return "bandage"
        }
    }
}

struct HexagonBadgeView: View {
    let type: BadgeType
    let isActive: Bool
    @State private var pulseScale: CGFloat = 1.0
    
    var body: some View {
        VStack(spacing: 6) {
            ZStack {
                HexagonShape()
                    .fill(LinearGradient(colors: [type.color.opacity(isActive ? 0.3 : 0.1), type.color.opacity(isActive ? 0.15 : 0.05)], startPoint: .top, endPoint: .bottom))
                    .overlay(HexagonShape().stroke(type.color.opacity(isActive ? 0.8 : 0.3), lineWidth: 1.5))
                    .frame(width: 44, height: 44)
                    .shadow(color: isActive ? type.color.opacity(0.4) : .clear, radius: 8)
                Image(systemName: type.icon).font(.system(size: 16, weight: .semibold)).foregroundStyle(type.color.opacity(isActive ? 1.0 : 0.5))
            }
            .scaleEffect(pulseScale)
            // FIX: Use old onChange syntax for iOS < 17 compatibility
            .onChange(of: isActive) { newValue in
                if newValue {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.6)) {
                        pulseScale = 1.1
                    }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
                        withAnimation(.spring(response: 0.3, dampingFraction: 0.6)) {
                            pulseScale = 1.0
                        }
                    }
                }
            }
            Text(type.rawValue).font(.system(size: 10, weight: .medium)).foregroundStyle(type.color.opacity(isActive ? 0.9 : 0.4))
        }
    }
}

struct HexagonShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let radius = min(rect.width, rect.height) / 2
        for i in 0..<6 {
            let angle = Double(i) * .pi / 3 - .pi / 2
            let x = center.x + cos(angle) * radius
            let y = center.y + sin(angle) * radius
            if i == 0 { path.move(to: CGPoint(x: x, y: y)) } else { path.addLine(to: CGPoint(x: x, y: y)) }
        }
        path.closeSubpath()
        return path
    }
}

struct BadgeContainerView: View {
    let activeBadges: Set<BadgeType>
    let stage: JailbreakStage
    
    var body: some View {
        HStack(spacing: 16) {
            ForEach(BadgeType.allCases, id: \.self) { type in
                HexagonBadgeView(type: type, isActive: activeBadges.contains(type))
            }
        }
    }
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

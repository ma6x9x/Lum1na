import SwiftUI

enum JailbreakStage: String, CaseIterable {
    case idle = "IDLE"
    case kaslr = "KASLR"
    case heap = "HEAP"
    case ane = "ANE"
    case ppl = "PPL"
    case persist = "PERSIST"
    
    var color: Color {
        switch self {
        case .idle:     return .lum1naViolet
        case .kaslr:    return .lum1naCyan
        case .heap:     return .lum1naVioletPurple
        case .ane:      return .lum1naBlue
        case .ppl:      return .lum1naMagenta
        case .persist:  return .lum1naPink
        }
    }
    
    var glowColor: Color {
        color.opacity(0.6)
    }
}

extension Color {
    static let lum1naField = Color(hex: "#07060F")
    static let lum1naViolet = Color(hex: "#8B5CF6")
    static let lum1naVioletPurple = Color(hex: "#A855F7")
    static let lum1naCyan = Color(hex: "#06B6D4")
    static let lum1naBlue = Color(hex: "#3B82F6")
    static let lum1naMagenta = Color(hex: "#D946EF")
    static let lum1naPink = Color(hex: "#EC4899")
    static let consoleBackground = Color(hex: "#0A0A0F")
    static let consoleText = Color(hex: "#E2E8F0")
    static let consoleTimestamp = Color(hex: "#64748B")
    static let consoleInfo = Color(hex: "#22D3EE")
    static let consoleSuccess = Color(hex: "#4ADE80")
    static let consoleWarning = Color(hex: "#FBBF24")
    static let consoleError = Color(hex: "#F87171")
    static let circuitLine = Color(hex: "#1E293B")
    static let circuitNode = Color(hex: "#334155")
    static let badgeKernel = Color(hex: "#EF4444")
    static let badgeSandbox = Color(hex: "#F59E0B")
    static let badgeDaemon = Color(hex: "#10B981")
    static let badgePatchset = Color(hex: "#3B82F6")
    
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

extension Font {
    static let console = Font.system(.caption, design: .monospaced)
    static let consoleSmall = Font.system(.caption2, design: .monospaced)
    static let beaconTitle = Font.system(.title2, weight: .semibold)
    static let badgeLabel = Font.system(.caption, weight: .medium)
    static let heapAddress = Font.system(.callout, design: .monospaced)
    static let buttonLabel = Font.system(.subheadline, weight: .medium)
}

enum LayoutConstants {
    static let starSize: CGFloat = 80
    static let hexagonSize: CGFloat = 60
    static let badgeSize: CGFloat = 44
    static let consoleHeight: CGFloat = 180
    static let circuitLineWidth: CGFloat = 1.5
    static let cornerRadius: CGFloat = 16
}

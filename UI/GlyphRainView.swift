import SwiftUI

/// Soft matrix rain in the content layer (not glass).
struct GlyphRainView: View {
    var intensity: Double = 1
    private let glyphs = Array("01Δλ◇◆*+· consK#%$@")
    private let columns = 18

    var body: some View {
        TimelineView(.animation(minimumInterval: 0.12, paused: false)) { context in
            Canvas { ctx, size in
                let colW = size.width / CGFloat(columns)
                let tick = context.date.timeIntervalSinceReferenceDate
                for c in 0..<columns {
                    let seed = Double(c) * 12.7
                    let speed = 28 + (seed.truncatingRemainder(dividingBy: 40))
                    let yOff = (tick * speed + seed * 17).truncatingRemainder(dividingBy: Double(size.height + 80))
                    for row in 0..<14 {
                        let y = CGFloat(yOff) + CGFloat(row) * 18 - 40
                        let idx = abs(c * 31 + row * 7 + Int(tick * 3)) % glyphs.count
                        let ch = String(glyphs[idx])
                        let alpha = (0.05 + Double(row) * 0.008) * intensity
                        // FIX: Use explicit Color instead of Lum1naPalette.rain
                        ctx.draw(
                            Text(ch)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(Color(hex: "#06B6D4").opacity(alpha)),
                            at: CGPoint(x: CGFloat(c) * colW + colW * 0.35, y: y),
                            anchor: .topLeading
                        )
                    }
                }
            }
        }
        .allowsHitTesting(false)
        .ignoresSafeArea()
    }
}

// Color extension for hex support
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

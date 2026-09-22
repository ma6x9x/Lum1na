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

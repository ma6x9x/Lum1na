import SwiftUI

/// Four-pointed Lum1na sparkle. No ring, no circle — the logo is the board core.
struct Lum1naStarShape: Shape {
    var innerRatio: CGFloat = 0.22

    func path(in rect: CGRect) -> Path {
        var path = Path()
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let outer = min(rect.width, rect.height) / 2
        let inner = outer * innerRatio
        for i in 0..<4 {
            let outerAngle = Double(i) * .pi / 2 - .pi / 2
            let innerAngle = outerAngle + .pi / 4
            let ox = center.x + CGFloat(cos(outerAngle)) * outer
            let oy = center.y + CGFloat(sin(outerAngle)) * outer
            let ix = center.x + CGFloat(cos(innerAngle)) * inner
            let iy = center.y + CGFloat(sin(innerAngle)) * inner
            if i == 0 {
                path.move(to: CGPoint(x: ox, y: oy))
            } else {
                path.addLine(to: CGPoint(x: ox, y: oy))
            }
            path.addLine(to: CGPoint(x: ix, y: iy))
        }
        path.closeSubpath()
        return path
    }
}

struct Lum1naStarMark: View {
    var motion: BoardMotion = .idle
    var stageColor: Color
    var tickAt: Date = .distantPast
    var reduceMotion: Bool = false

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: false)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            let amp = reduceMotion ? 0 : motion.starAmp
            let breathe = 1.0 + CGFloat(sin(t * (motion == .failed ? 0.64 : 1.6))) * amp
            let tickBoost: CGFloat = {
                guard !reduceMotion else { return 1 }
                let age = context.date.timeIntervalSince(tickAt)
                if age >= 0 && age < 0.18 { return 1.12 }
                return 1
            }()
            let coreFlash: CGFloat = {
                guard !reduceMotion, motion == .idle else { return 0 }
                let beat = t.truncatingRemainder(dividingBy: 4.0)
                return beat < 0.06 ? 0.08 : 0
            }()
            let hue: Color = {
                switch motion {
                case .success: return .consoleSuccess
                case .failed, .recovered: return .consoleError
                default: return stageColor
                }
            }()
            let settle: CGFloat = {
                switch motion {
                case .success: return 1.08
                case .failed: return 0.86
                default: return 1
                }
            }()

            ZStack {
                Lum1naStarShape()
                    .fill(starGradient)
                    .blur(radius: motion.starBloom)
                    .opacity(0.55)
                    .scaleEffect(breathe * 1.15 * settle)

                Lum1naStarShape()
                    .fill(starGradient)
                    .shadow(color: Color.lum1naMagenta.opacity(0.55), radius: 10, x: -4, y: 0)
                    .shadow(color: Color.lum1naCyan.opacity(0.55), radius: 10, x: 4, y: 0)
                    .shadow(color: hue.opacity(0.45), radius: 14)
                    .scaleEffect(breathe * settle * tickBoost)

                Lum1naStarShape()
                    .fill(Color.white.opacity(0.55 + Double(coreFlash)))
                    .frame(width: 34, height: 34)
                    .blur(radius: 0.6)
                    .scaleEffect(breathe * (1 + coreFlash) * settle)
            }
            .frame(width: 132, height: 132)
        }
        .accessibilityLabel("Lum1na")
    }

    private var starGradient: LinearGradient {
        LinearGradient(
            colors: [
                Color(hex: "#E879F9"),
                Color.white,
                Color(hex: "#22D3EE")
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }
}

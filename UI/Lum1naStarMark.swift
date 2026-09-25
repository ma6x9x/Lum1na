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
    var running: Bool
    var stageColor: Color

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: false)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            let breathe = 1.0 + CGFloat(sin(t * 1.6)) * (running ? 0.06 : 0.03)
            ZStack {
                Lum1naStarShape()
                    .fill(starGradient)
                    .blur(radius: running ? 18 : 12)
                    .opacity(0.55)
                    .scaleEffect(breathe * 1.15)

                Lum1naStarShape()
                    .fill(starGradient)
                    .shadow(color: Color.lum1naMagenta.opacity(0.55), radius: 10, x: -4, y: 0)
                    .shadow(color: Color.lum1naCyan.opacity(0.55), radius: 10, x: 4, y: 0)
                    .shadow(color: stageColor.opacity(running ? 0.45 : 0.2), radius: 14)
                    .scaleEffect(breathe)

                Lum1naStarShape()
                    .fill(Color.white.opacity(0.55))
                    .frame(width: 28, height: 28)
                    .blur(radius: 0.6)
                    .scaleEffect(breathe)
            }
            .frame(width: 108, height: 108)
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

import SwiftUI

/// Quiet star field. No glyph rain, no PCB grid.
struct GalaxyFieldView: View {
    var accent: Color
    var speed: Double = 1.0

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 24.0, paused: false)) { context in
            let t = context.date.timeIntervalSinceReferenceDate * speed
            Canvas { ctx, size in
                ctx.fill(
                    Path(CGRect(origin: .zero, size: size)),
                    with: .color(Color(hex: "#03010A"))
                )
                ctx.fill(
                    Path(CGRect(origin: .zero, size: size)),
                    with: .radialGradient(
                        Gradient(colors: [
                            accent.opacity(0.20),
                            Color.lum1naMagenta.opacity(0.10),
                            Color.clear
                        ]),
                        center: CGPoint(x: size.width * 0.5, y: size.height * 0.36),
                        startRadius: 10,
                        endRadius: min(size.width, size.height) * 0.65
                    )
                )
                for i in 0..<90 {
                    let seed = CGFloat((i * 47) % 997)
                    let x = (seed * 17).truncatingRemainder(dividingBy: max(size.width, 1))
                    let y = (seed * 29).truncatingRemainder(dividingBy: max(size.height, 1))
                    let twinkle = 0.25 + 0.75 * (0.5 + 0.5 * sin(t * 0.7 + Double(i)))
                    let r: CGFloat = i % 9 == 0 ? 1.6 : 0.7
                    let col = i % 5 == 0 ? Color.lum1naCyan : (i % 5 == 1 ? Color.lum1naMagenta : Color.white)
                    ctx.fill(
                        Path(ellipseIn: CGRect(x: x, y: y, width: r * 2, height: r * 2)),
                        with: .color(col.opacity(twinkle * 0.55))
                    )
                }
            }
        }
        .ignoresSafeArea()
        .allowsHitTesting(false)
    }
}

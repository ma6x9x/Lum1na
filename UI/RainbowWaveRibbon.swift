import SwiftUI

/// Pure-SwiftUI rainbow ribbon (MetalKit-free for unsigned CI builds).
/// Same public surface StarBeaconView already uses: `RainbowWaveRibbonView(power:)`.
struct RainbowWaveRibbonView: View {
    var power: Double

    private var clamped: Double {
        min(1, max(0, power))
    }

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: false)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            Canvas { ctx, size in
                let midY = size.height * 0.5
                let amplitude = 6 + CGFloat(clamped) * 16
                let bands: [(Color, CGFloat)] = [
                    (Color(red: 1.00, green: 0.20, blue: 0.55), -3),
                    (Color(red: 1.00, green: 0.55, blue: 0.12), -1),
                    (Color(red: 0.20, green: 0.95, blue: 0.45), 1),
                    (Color(red: 0.25, green: 0.55, blue: 1.00), 3)
                ]

                for (color, yBias) in bands {
                    var path = Path()
                    let steps = max(24, Int(size.width / 6))
                    for i in 0...steps {
                        let x = size.width * CGFloat(i) / CGFloat(steps)
                        let phase = t * (1.6 + clamped * 2.2) + Double(x) * 0.045 + Double(yBias) * 0.35
                        let y = midY + yBias * 2.2 + CGFloat(sin(phase)) * amplitude
                        if i == 0 {
                            path.move(to: CGPoint(x: x, y: y))
                        } else {
                            path.addLine(to: CGPoint(x: x, y: y))
                        }
                    }
                    ctx.stroke(
                        path,
                        with: .color(color.opacity(0.35 + clamped * 0.55)),
                        style: StrokeStyle(
                            lineWidth: 2.2 + CGFloat(clamped) * 2.8,
                            lineCap: .round,
                            lineJoin: .round
                        )
                    )
                }
            }
        }
        .blur(radius: 0.4)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

#Preview {
    ZStack {
        Color.black.ignoresSafeArea()
        RainbowWaveRibbonView(power: 0.7)
            .frame(height: 80)
            .padding()
    }
}

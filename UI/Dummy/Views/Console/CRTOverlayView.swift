import SwiftUI

/// The tube, re-implemented from the synth-ui CRT ideas in plain SwiftUI:
/// scanlines (dim gaps between beam rows), a fine RGB aperture-grille mask,
/// a vignette, a curved-glass glare, faint flicker and a rolling refresh bar.
/// Flicker and roll stop when motion is reduced or off.
struct CRTOverlayView: View {
    @Environment(\.luminaMotion) private var motion

    var body: some View {
        ZStack {
            Canvas { context, size in
                drawScanlinesAndMask(in: &context, size: size)
            }
            RadialGradient(
                colors: [.clear, .clear, .black.opacity(0.55)],
                center: .center, startRadius: 0, endRadius: 260
            )
            .scaleEffect(x: 1.25, y: 1)
            LinearGradient(
                stops: [.init(color: .white.opacity(0.07), location: 0), .init(color: .clear, location: 0.3)],
                startPoint: .topLeading, endPoint: .bottomTrailing
            )
            if motion.allowsContinuousMotion {
                TimelineView(.animation(minimumInterval: 1.0 / 30.0)) { timeline in
                    Canvas { context, size in
                        drawRollAndFlicker(in: &context, size: size, t: timeline.date.timeIntervalSinceReferenceDate)
                    }
                }
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private func drawScanlinesAndMask(in context: inout GraphicsContext, size: CGSize) {
        var scan = Path()
        var y: CGFloat = 1.5
        while y < size.height {
            scan.addRect(CGRect(x: 0, y: y, width: size.width, height: 1.5))
            y += 3
        }
        context.fill(scan, with: .color(.black.opacity(0.34)))

        var red = Path()
        var green = Path()
        var blue = Path()
        var x: CGFloat = 0
        while x < size.width {
            red.addRect(CGRect(x: x, y: 0, width: 1, height: size.height))
            green.addRect(CGRect(x: x + 1, y: 0, width: 1, height: size.height))
            blue.addRect(CGRect(x: x + 2, y: 0, width: 1, height: size.height))
            x += 3
        }
        context.blendMode = .screen
        context.fill(red, with: .color(Color(red: 1, green: 0.16, blue: 0.35).opacity(0.055)))
        context.fill(green, with: .color(Color(red: 0.16, green: 1, blue: 0.59).opacity(0.045)))
        context.fill(blue, with: .color(Color(red: 0.24, green: 0.47, blue: 1).opacity(0.06)))
    }

    private func drawRollAndFlicker(in context: inout GraphicsContext, size: CGSize, t: Double) {
        let p = (t.truncatingRemainder(dividingBy: 5.5)) / 5.5
        let barHeight: CGFloat = 46
        let y = -60 + CGFloat(p) * (size.height + 80)
        context.fill(
            Path(CGRect(x: 0, y: y, width: size.width, height: barHeight)),
            with: .linearGradient(
                Gradient(colors: [.clear, Palette.phosphor.opacity(0.09), .clear]),
                startPoint: CGPoint(x: 0, y: y), endPoint: CGPoint(x: 0, y: y + barHeight)
            )
        )
        let flicker = 0.035 * HexDump.noise((t * 30).rounded(.down))
        context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(.black.opacity(flicker)))
    }
}

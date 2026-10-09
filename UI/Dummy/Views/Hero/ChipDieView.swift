import SwiftUI

/// The fine inner die pattern under the star: a micro-grid, a dashed seal
/// ring and a radial violet glow. Static `Canvas`, drawn once per size.
struct ChipDieView: View {
    var body: some View {
        Canvas { context, size in
            let rect = CGRect(origin: .zero, size: size)
            let shape = Path(roundedRect: rect, cornerRadius: 8)
            context.fill(shape, with: .radialGradient(
                Gradient(colors: [Palette.violet.opacity(0.35), Color(red: 0.04, green: 0.03, blue: 0.12).opacity(0.92)]),
                center: CGPoint(x: size.width / 2, y: size.height / 2), startRadius: 0, endRadius: size.width * 0.7
            ))
            var grid = Path()
            var x: CGFloat = 3
            while x < size.width { grid.move(to: CGPoint(x: x, y: 0)); grid.addLine(to: CGPoint(x: x, y: size.height)); x += 6 }
            var y: CGFloat = 3
            while y < size.height { grid.move(to: CGPoint(x: 0, y: y)); grid.addLine(to: CGPoint(x: size.width, y: y)); y += 6 }
            context.clip(to: shape)
            context.stroke(grid, with: .color(Palette.violet.opacity(0.16)), lineWidth: 0.6)
            let seal = Path(roundedRect: rect.insetBy(dx: 7, dy: 7), cornerRadius: 5)
            context.stroke(seal, with: .color(Palette.cyan.opacity(0.25)), style: StrokeStyle(lineWidth: 0.8, dash: [3, 2]))
            context.stroke(shape, with: .color(Palette.violet.opacity(0.45)), lineWidth: 1)
        }
        .accessibilityHidden(true)
    }
}

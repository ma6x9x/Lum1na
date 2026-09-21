import SwiftUI

/// Hero mark matching the Lum1na logo: 4-point star in a glass orb with
/// purple→cyan electric filaments. Idle = mostly static; running = neuron spark.
struct StarBeaconView: View {
    var isActive: Bool
    /// 0...1 intensity (from ExploitManager.isRunning — UI only).
    var power: Double = 0.15

    @State private var breath = false
    @State private var sparkPhase: Double = 0

    private let orbSize: CGFloat = 168

    var body: some View {
        ZStack {
            // Soft nebula bloom
            Circle()
                .fill(
                    RadialGradient(
                        colors: [
                            Lum1naPalette.magenta.opacity(isActive ? 0.40 : 0.22),
                            Lum1naPalette.violet.opacity(0.16),
                            Lum1naPalette.ice.opacity(0.06),
                            .clear
                        ],
                        center: .center,
                        startRadius: 8,
                        endRadius: 130
                    )
                )
                .frame(width: 260, height: 260)
                .blur(radius: 10)
                .scaleEffect(breath ? 1.05 : 0.96)

            TimelineView(.animation(minimumInterval: isActive ? 1.0 / 30.0 : 1.0 / 8.0, paused: false)) { context in
                let t = context.date.timeIntervalSinceReferenceDate
                let phase = isActive ? t * (1.4 + clampedPower * 2.2) : t * 0.25
                ElectricOrbCanvas(isActive: isActive, power: clampedPower, phase: phase)
                    .frame(width: orbSize, height: orbSize)
            }
            .scaleEffect(breath ? 1.02 : 0.99)
        }
        .frame(height: 220)
        .onAppear { startBreath() }
        .onChange(of: isActive) { active in
            if active {
                withAnimation(.easeInOut(duration: 0.7).repeatForever(autoreverses: true)) {
                    breath = true
                }
            } else {
                startBreath()
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(isActive ? "LUM1NA beacon active" : "LUM1NA beacon")
        .accessibilityAddTraits(.isImage)
    }

    private var clampedPower: Double {
        min(1, max(0, power))
    }

    private func startBreath() {
        withAnimation(.easeInOut(duration: 3.6).repeatForever(autoreverses: true)) {
            breath = true
        }
    }
}

// MARK: - Canvas orb

private struct ElectricOrbCanvas: View {
    var isActive: Bool
    var power: Double
    var phase: Double

    var body: some View {
        Canvas { ctx, size in
            let mid = CGPoint(x: size.width / 2, y: size.height / 2)
            let r = min(size.width, size.height) / 2

            drawFilaments(ctx: ctx, mid: mid, r: r)
            drawGlassRing(ctx: ctx, mid: mid, r: r)
            drawStar(ctx: ctx, mid: mid, r: r)
            if isActive {
                drawSparks(ctx: ctx, mid: mid, r: r)
            }
        }
    }

    private func drawFilaments(ctx: GraphicsContext, mid: CGPoint, r: CGFloat) {
        let count = 14
        for i in 0..<count {
            let base = Double(i) / Double(count) * .pi * 2
            let sweep = base + phase * (i.isMultiple(of: 2) ? 0.35 : -0.28)
            let reach = r * CGFloat(0.92 + 0.18 * sin(phase * 1.7 + Double(i)))
            let side = i < count / 2
            let color = side
                ? Color(red: 0.85, green: 0.25, blue: 0.95).opacity(isActive ? 0.55 : 0.28)
                : Color(red: 0.25, green: 0.85, blue: 1.0).opacity(isActive ? 0.55 : 0.28)

            var path = Path()
            let steps = 18
            for s in 0...steps {
                let u = CGFloat(s) / CGFloat(steps)
                let ang = sweep + Double(u) * 0.55 + 0.12 * sin(phase * 3 + Double(i) + Double(s) * 0.4)
                let rad = r * 0.38 + (reach - r * 0.38) * u
                let jitter = CGFloat(sin(phase * 4 + Double(i * 3 + s))) * (isActive ? 3.5 : 1.2) * CGFloat(power + 0.25)
                let x = mid.x + CGFloat(cos(ang)) * rad + jitter
                let y = mid.y + CGFloat(sin(ang)) * rad + jitter * 0.6
                if s == 0 { path.move(to: CGPoint(x: x, y: y)) }
                else { path.addLine(to: CGPoint(x: x, y: y)) }
            }
            ctx.stroke(
                path,
                with: .color(color),
                style: StrokeStyle(lineWidth: isActive ? 1.6 : 1.1, lineCap: .round, lineJoin: .round)
            )
        }
    }

    private func drawGlassRing(ctx: GraphicsContext, mid: CGPoint, r: CGFloat) {
        let ringR = r * 0.42
        let ring = Path(ellipseIn: CGRect(x: mid.x - ringR, y: mid.y - ringR, width: ringR * 2, height: ringR * 2))
        ctx.stroke(
            ring,
            with: .linearGradient(
                Gradient(colors: [
                    Color.white.opacity(0.85),
                    Lum1naPalette.magenta.opacity(0.7),
                    Lum1naPalette.ice.opacity(0.8),
                    Color.white.opacity(0.5)
                ]),
                startPoint: CGPoint(x: mid.x - ringR, y: mid.y - ringR),
                endPoint: CGPoint(x: mid.x + ringR, y: mid.y + ringR)
            ),
            lineWidth: 3.2
        )
        ctx.stroke(ring, with: .color(Color.white.opacity(0.25)), lineWidth: 1)
    }

    private func drawStar(ctx: GraphicsContext, mid: CGPoint, r: CGFloat) {
        let outer = r * 0.28
        let inner = r * 0.08
        var star = Path()
        for i in 0..<8 {
            let ang = -Double.pi / 2 + Double(i) * Double.pi / 4
            let rad = (i % 2 == 0) ? outer : inner
            let pt = CGPoint(x: mid.x + CGFloat(cos(ang)) * rad, y: mid.y + CGFloat(sin(ang)) * rad)
            if i == 0 { star.move(to: pt) } else { star.addLine(to: pt) }
        }
        star.closeSubpath()

        ctx.fill(
            star,
            with: .radialGradient(
                Gradient(colors: [Color.white, Lum1naPalette.magenta.opacity(0.9), Lum1naPalette.violet.opacity(0.5)]),
                center: mid,
                startRadius: 0,
                endRadius: outer
            )
        )
        ctx.drawLayer { layer in
            layer.addFilter(.shadow(color: Lum1naPalette.magenta.opacity(isActive ? 0.9 : 0.55), radius: isActive ? 14 : 8))
            layer.fill(star, with: .color(Color.white.opacity(0.95)))
        }
    }

    private func drawSparks(ctx: GraphicsContext, mid: CGPoint, r: CGFloat) {
        for i in 0..<10 {
            let ang = phase * 1.3 + Double(i) * 0.62
            let dist = r * CGFloat(0.5 + 0.35 * abs(sin(phase * 2.1 + Double(i))))
            let p = CGPoint(x: mid.x + CGFloat(cos(ang)) * dist, y: mid.y + CGFloat(sin(ang)) * dist)
            let spark = Path(ellipseIn: CGRect(x: p.x - 1.5, y: p.y - 1.5, width: 3, height: 3))
            let col = i.isMultiple(of: 2) ? Lum1naPalette.ice : Lum1naPalette.magenta
            ctx.fill(spark, with: .color(col.opacity(0.45 + 0.4 * abs(sin(phase + Double(i))))))
        }
    }
}

#Preview {
    ZStack {
        Lum1naPalette.field.ignoresSafeArea()
        VStack(spacing: 28) {
            StarBeaconView(isActive: false, power: 0.15)
            StarBeaconView(isActive: true, power: 0.85)
        }
    }
}

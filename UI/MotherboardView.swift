import SwiftUI

/// Motherboard: star at the hub, orthogonal traces to the four chain pads.
/// Pads light when that stage is selected/running. No center circle.
struct MotherboardView: View {
    @ObservedObject var manager: ExploitManager
    let onSelectStage: (ExploitStage) -> Void

    var body: some View {
        GeometryReader { geo in
            let size = geo.size
            let center = CGPoint(x: size.width * 0.5, y: size.height * 0.5)
            let pads = padPoints(in: size)

            ZStack {
                MotherboardTraceLayer(
                    center: center,
                    pads: pads,
                    active: manager.selectedStage,
                    fireLasers: manager.fullChainActive,
                    progress: manager.progress
                )

                ForEach(ExploitStage.allCases) { stage in
                    let pt = pads[stage] ?? center
                    Button {
                        onSelectStage(stage)
                    } label: {
                        MotherboardPad(
                            stage: stage,
                            isActive: manager.selectedStage == stage,
                            isRunning: manager.isRunning && manager.selectedStage == stage
                        )
                    }
                    .buttonStyle(PlainButtonStyle())
                    .disabled(manager.isRunning)
                    .position(pt)
                }

                Lum1naStarMark(
                    running: manager.fullChainActive,
                    stageColor: (manager.selectedStage ?? .kernel).color
                )
                .position(center)
                .allowsHitTesting(false)
            }
        }
    }

    private func padPoints(in size: CGSize) -> [ExploitStage: CGPoint] {
        [
            .kernel:   CGPoint(x: size.width * 0.50, y: size.height * 0.18),
            .sandbox:  CGPoint(x: size.width * 0.84, y: size.height * 0.50),
            .daemon:   CGPoint(x: size.width * 0.50, y: size.height * 0.82),
            .patchset: CGPoint(x: size.width * 0.16, y: size.height * 0.50)
        ]
    }
}

struct MotherboardPad: View {
    let stage: ExploitStage
    let isActive: Bool
    let isRunning: Bool

    var body: some View {
        VStack(spacing: 4) {
            ZStack {
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(stage.color.opacity(isActive ? 0.18 : 0.06))
                    .frame(width: 58, height: 58)
                    .luminaGlassRect(14)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .stroke(stage.color.opacity(isActive ? 0.9 : 0.35), lineWidth: isActive ? 1.4 : 0.8)
                    )
                    .shadow(color: isActive ? stage.color.opacity(0.55) : .clear, radius: isActive ? 10 : 0)

                if isRunning {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: stage.color))
                        .scaleEffect(0.75)
                } else {
                    Image(systemName: stage.icon)
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundColor(stage.color)
                }
            }
            Text(stage.displayName)
                .font(.system(size: 9, weight: .bold, design: .rounded))
                .foregroundColor(isActive ? stage.color : Color.white.opacity(0.55))
                .tracking(0.6)
        }
    }
}

struct MotherboardTraceLayer: View {
    let center: CGPoint
    let pads: [ExploitStage: CGPoint]
    let active: ExploitStage?
    let fireLasers: Bool
    let progress: Double

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: false)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            Canvas { ctx, size in
                for stage in ExploitStage.allCases {
                    guard let dest = pads[stage] else { continue }
                    let lit = fireLasers && active == stage
                    let traces = manhattanBundle(from: center, to: dest)
                    for (i, path) in traces.enumerated() {
                        let opacity: Double = lit ? 0.95 : 0.06
                        let w: CGFloat = lit ? (i == 0 ? 2.4 : 1.1) : 0.5
                        ctx.stroke(path, with: .color(stage.color.opacity(opacity)), lineWidth: w)
                        if lit {
                            ctx.stroke(path, with: .color(stage.color.opacity(0.28)), lineWidth: 8)
                        }
                    }
                    if lit {
                        let speed = 0.55 + progress * 0.9
                        for k in 0..<4 {
                            let packetT = (t * speed + Double(k) * 0.22).truncatingRemainder(dividingBy: 1.0)
                            let p = pointOnOrthogonal(from: center, to: dest, t: packetT)
                            let r: CGFloat = 5.5
                            let rect = CGRect(x: p.x - r, y: p.y - r, width: r * 2, height: r * 2)
                            ctx.fill(Path(ellipseIn: rect.insetBy(dx: -5, dy: -5)), with: .color(stage.color.opacity(0.28)))
                            ctx.fill(Path(ellipseIn: rect), with: .color(stage.color))
                            ctx.fill(Path(ellipseIn: rect.insetBy(dx: 1.8, dy: 1.8)), with: .color(.white.opacity(0.85)))
                        }
                    }
                }
            }
        }
        .allowsHitTesting(false)
    }

    private func drawBoard(ctx: GraphicsContext, size: CGSize, t: Double) {
        let inset: CGFloat = 6
        let board = CGRect(x: inset, y: inset, width: size.width - inset * 2, height: size.height - inset * 2)
        ctx.stroke(
            Path(roundedRect: board, cornerRadius: 10),
            with: .color(Color(hex: "#7C3AED").opacity(0.45)),
            lineWidth: 1.4
        )
        let pinN = 18
        for i in 0..<pinN {
            let u = CGFloat(i) / CGFloat(pinN - 1)
            let pulse = 0.35 + 0.65 * (0.5 + 0.5 * sin(t * 2.2 + Double(i) * 0.4))
            let c = i % 2 == 0 ? Color.lum1naCyan : Color.lum1naMagenta
            let pts: [CGPoint] = [
                CGPoint(x: board.minX, y: board.minY + board.height * u),
                CGPoint(x: board.maxX, y: board.minY + board.height * u),
                CGPoint(x: board.minX + board.width * u, y: board.minY),
                CGPoint(x: board.minX + board.width * u, y: board.maxY)
            ]
            for p in pts {
                let r: CGFloat = 1.6
                ctx.fill(
                    Path(ellipseIn: CGRect(x: p.x - r, y: p.y - r, width: r * 2, height: r * 2)),
                    with: .color(c.opacity(pulse))
                )
            }
        }
    }

    private func manhattanBundle(from a: CGPoint, to b: CGPoint) -> [Path] {
        let dx = b.x - a.x
        let dy = b.y - a.y
        let start: CGPoint
        if abs(dx) > abs(dy) {
            start = CGPoint(x: a.x + (dx > 0 ? 30 : -30), y: a.y)
        } else {
            start = CGPoint(x: a.x, y: a.y + (dy > 0 ? 30 : -30))
        }
        func elbow(_ offset: CGFloat) -> Path {
            var path = Path()
            let s = CGPoint(x: start.x, y: start.y + offset)
            let mid = CGPoint(x: b.x, y: s.y)
            path.move(to: s)
            path.addLine(to: mid)
            path.addLine(to: CGPoint(x: b.x, y: b.y + offset * 0.3))
            return path
        }
        if abs(dx) > abs(dy) {
            return [elbow(0), elbow(7), elbow(-7)]
        }
        func tee(_ offset: CGFloat) -> Path {
            var path = Path()
            let s = CGPoint(x: start.x + offset, y: start.y)
            let mid = CGPoint(x: s.x, y: b.y)
            path.move(to: s)
            path.addLine(to: mid)
            path.addLine(to: CGPoint(x: b.x, y: b.y))
            return path
        }
        return [tee(0), tee(7), tee(-7)]
    }

    private func fillVia(_ ctx: GraphicsContext, at point: CGPoint, color: Color, lit: Bool) {
        let s: CGFloat = lit ? 5 : 3.2
        let rect = CGRect(x: point.x - s / 2, y: point.y - s / 2, width: s, height: s)
        ctx.fill(Path(roundedRect: rect, cornerRadius: 1), with: .color(color.opacity(lit ? 0.95 : 0.4)))
    }

    private func pointOnOrthogonal(from a: CGPoint, to b: CGPoint, t: Double) -> CGPoint {
        let clamped = CGFloat(max(0, min(1, t)))
        return CGPoint(x: a.x + (b.x - a.x) * clamped, y: a.y + (b.y - a.y) * clamped)
    }

    private func midpoint(_ a: CGPoint, _ b: CGPoint) -> CGPoint {
        CGPoint(x: (a.x + b.x) / 2, y: (a.y + b.y) / 2)
    }
}

/// Nephew-sketch clouds, redrawn as faint neon outlines so they stay on-theme.
struct CloudWispsView: View {
    var body: some View {
        HStack(spacing: -8) {
            cloud(width: 54, height: 22)
            cloud(width: 72, height: 28)
            cloud(width: 48, height: 20)
        }
        .opacity(0.35)
        .allowsHitTesting(false)
    }

    private func cloud(width: CGFloat, height: CGFloat) -> some View {
        Capsule()
            .stroke(
                LinearGradient(
                    colors: [Color.lum1naCyan.opacity(0.7), Color.lum1naViolet.opacity(0.7)],
                    startPoint: .leading,
                    endPoint: .trailing
                ),
                lineWidth: 1
            )
            .frame(width: width, height: height)
    }
}

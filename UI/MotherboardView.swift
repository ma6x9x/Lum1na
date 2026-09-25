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
                    running: manager.isRunning,
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
                    running: manager.isRunning,
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
                RoundedRectangle(cornerRadius: 12)
                    .fill(
                        LinearGradient(
                            colors: [
                                stage.color.opacity(isActive ? 0.28 : 0.08),
                                Color(hex: "#0A0A0F").opacity(0.9)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(stage.color.opacity(isActive ? 0.95 : 0.35), lineWidth: isActive ? 1.6 : 1)
                    )
                    .frame(width: 58, height: 58)
                    .shadow(color: isActive ? stage.color.opacity(0.45) : .clear, radius: 8)

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
    let running: Bool
    let progress: Double

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: false)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            Canvas { ctx, _ in
                for stage in ExploitStage.allCases {
                    guard let dest = pads[stage] else { continue }
                    let lit = active == stage
                    let path = orthogonalTrace(from: center, to: dest)
                    let color = lit ? stage.color : Color(hex: "#334155")
                    ctx.stroke(path, with: .color(color.opacity(lit ? 0.95 : 0.35)), lineWidth: lit ? 2.2 : 1.1)

                    if lit {
                        let glow = path
                        ctx.stroke(glow, with: .color(stage.color.opacity(0.25)), lineWidth: 7)
                    }

                    let via = viaRect(at: midpoint(center, dest))
                    ctx.fill(Path(via), with: .color(color.opacity(lit ? 0.9 : 0.4)))

                    if lit && running {
                        let packetT = (t * (0.45 + progress * 0.8)).truncatingRemainder(dividingBy: 1.0)
                        let p = pointOnOrthogonal(from: center, to: dest, t: packetT)
                        let r: CGFloat = 4.5
                        let rect = CGRect(x: p.x - r, y: p.y - r, width: r * 2, height: r * 2)
                        ctx.fill(Path(ellipseIn: rect), with: .color(stage.color))
                        ctx.fill(
                            Path(ellipseIn: rect.insetBy(dx: -4, dy: -4)),
                            with: .color(stage.color.opacity(0.25))
                        )
                    }
                }
            }
        }
        .allowsHitTesting(false)
    }

    /// PCB-style: leave the star, then a straight run to the pad.
    private func orthogonalTrace(from a: CGPoint, to b: CGPoint) -> Path {
        var path = Path()
        let dx = b.x - a.x
        let dy = b.y - a.y
        let start: CGPoint
        if abs(dx) > abs(dy) {
            start = CGPoint(x: a.x + (dx > 0 ? 28 : -28), y: a.y)
        } else {
            start = CGPoint(x: a.x, y: a.y + (dy > 0 ? 28 : -28))
        }
        path.move(to: start)
        path.addLine(to: b)
        return path
    }

    private func pointOnOrthogonal(from a: CGPoint, to b: CGPoint, t: Double) -> CGPoint {
        let clamped = CGFloat(max(0, min(1, t)))
        return CGPoint(x: a.x + (b.x - a.x) * clamped, y: a.y + (b.y - a.y) * clamped)
    }

    private func viaRect(at point: CGPoint) -> CGRect {
        let s: CGFloat = 4
        return CGRect(x: point.x - s / 2, y: point.y - s / 2, width: s, height: s)
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

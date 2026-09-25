import SwiftUI

/// Motherboard: star at the hub, orthogonal traces to the four chain pads.
/// Pads light when that stage is selected/running. No center circle.
struct MotherboardView: View {
    @ObservedObject var manager: ExploitManager
    var recovered: Bool = false
    var tickAt: Date = .distantPast
    let onSelectStage: (ExploitStage) -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var motion: BoardMotion {
        BoardMotion.from(manager, recovered: recovered)
    }

    var body: some View {
        GeometryReader { geo in
            let size = geo.size
            let center = CGPoint(x: size.width * 0.5, y: size.height * 0.5)
            let pads = padPoints(in: size)

            ZStack {
                MotherboardTraceLayer(
                    center: center,
                    pads: pads,
                    motion: motion,
                    progress: manager.progress,
                    reduceMotion: reduceMotion
                )

                ForEach(ExploitStage.allCases) { stage in
                    let pt = pads[stage] ?? center
                    Button {
                        onSelectStage(stage)
                    } label: {
                        MotherboardPad(
                            stage: stage,
                            motion: motion,
                            reduceMotion: reduceMotion
                        )
                    }
                    .buttonStyle(PlainButtonStyle())
                    .disabled(manager.isRunning)
                    .position(pt)
                }

                Lum1naStarMark(
                    motion: motion,
                    stageColor: (manager.selectedStage ?? .kernel).color,
                    tickAt: tickAt,
                    reduceMotion: reduceMotion
                )
                .position(center)
                .allowsHitTesting(false)
            }
        }
    }

    private func padPoints(in size: CGSize) -> [ExploitStage: CGPoint] {
        [
            .kernel:   CGPoint(x: size.width * 0.50, y: size.height * 0.16),
            .sandbox:  CGPoint(x: size.width * 0.84, y: size.height * 0.50),
            .daemon:   CGPoint(x: size.width * 0.50, y: size.height * 0.84),
            .patchset: CGPoint(x: size.width * 0.16, y: size.height * 0.50)
        ]
    }
}

struct MotherboardPad: View {
    let stage: ExploitStage
    let motion: BoardMotion
    let reduceMotion: Bool

    private let face: CGFloat = 80
    private let radius: CGFloat = 22

    private var isActive: Bool {
        switch motion {
        case .arming(let s), .firing(let s, _): return s == stage
        case .chaining: return motion.liveRails.contains(stage)
        case .success: return true
        default: return false
        }
    }

    private var isRunning: Bool {
        switch motion {
        case .firing(let s, _): return s == stage
        case .chaining: return motion.liveRails.contains(stage)
        default: return false
        }
    }

    private var scale: CGFloat {
        if reduceMotion { return 1 }
        switch motion {
        case .arming(let s): return s == stage ? 1.08 : 0.94
        case .firing(let s, _): return s == stage ? 1.06 : 0.94
        case .chaining: return isActive ? 1.06 : 0.92
        case .success: return 1.08
        case .failed: return 0.96
        default: return 1
        }
    }

    private var dim: Double {
        switch motion {
        case .arming(let s), .firing(let s, _): return s == stage ? 1 : 0.45
        case .chaining: return isActive ? 1 : 0.4
        case .failed: return 0.55
        default: return 1
        }
    }

    private var phase: Double {
        switch stage {
        case .kernel: return 0
        case .sandbox: return 1.6
        case .daemon: return 3.1
        case .patchset: return 4.7
        }
    }

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 24.0, paused: reduceMotion)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            let floatY: CGFloat = {
                guard !reduceMotion, motion == .idle else { return 0 }
                return CGFloat(sin(t + phase) * 2)
            }()
            let sheen: CGFloat = {
                guard isRunning, !reduceMotion else { return -1 }
                return CGFloat((t * 0.7).truncatingRemainder(dividingBy: 2.0) - 1.0)
            }()
            let charge: CGFloat = {
                if reduceMotion { return isActive ? 1 : 0 }
                if case .arming(let s) = motion, s == stage { return 1 }
                return 0
            }()

            VStack(spacing: 5) {
                ZStack {
                    RoundedRectangle(cornerRadius: radius, style: .continuous)
                        .fill(stage.color.opacity(isActive ? 0.18 : 0.06))
                        .frame(width: face, height: face)
                        .luminaGlassRect(radius)
                        .overlay(
                            RoundedRectangle(cornerRadius: radius, style: .continuous)
                                .stroke(stage.color.opacity(isActive ? 0.9 : 0.35),
                                        lineWidth: isActive ? 1.4 : 0.8)
                        )
                        .shadow(color: isActive ? stage.color.opacity(0.55) : .clear,
                                radius: isActive ? 10 : 0)

                    if isRunning && !reduceMotion {
                        RoundedRectangle(cornerRadius: radius, style: .continuous)
                            .fill(
                                LinearGradient(
                                    colors: [.clear, Color.white.opacity(0.28), .clear],
                                    startPoint: UnitPoint(x: sheen, y: 0.2),
                                    endPoint: UnitPoint(x: sheen + 0.45, y: 0.8)
                                )
                            )
                            .frame(width: face, height: face)
                            .allowsHitTesting(false)
                    }

                    RoundedRectangle(cornerRadius: radius, style: .continuous)
                        .trim(from: 0, to: charge)
                        .stroke(stage.color, style: StrokeStyle(lineWidth: 2, lineCap: .round))
                        .frame(width: face + 4, height: face + 4)
                        .animation(.easeOut(duration: 0.45), value: charge)
                        .allowsHitTesting(false)

                    Image(systemName: stage.icon)
                        .font(.system(size: 25, weight: .semibold))
                        .foregroundColor(stage.color)
                }
                .scaleEffect(scale)
                Text(stage.displayName)
                    .font(.system(size: 11, weight: .bold, design: .rounded))
                    .foregroundColor(isActive ? stage.color : Color.white.opacity(0.55))
                    .tracking(0.6)
            }
            .opacity(dim)
            .offset(y: floatY)
            .animation(.spring(response: 0.35, dampingFraction: 0.72), value: scale)
        }
    }
}

struct MotherboardTraceLayer: View {
    let center: CGPoint
    let pads: [ExploitStage: CGPoint]
    let motion: BoardMotion
    let progress: Double
    let reduceMotion: Bool

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: false)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            Canvas { ctx, _ in
                let rails = motion.liveRails
                let idleCrawl = !reduceMotion && motion == .idle
                let packetN = rails.isEmpty ? 1 : 7

                for stage in ExploitStage.allCases {
                    guard let dest = pads[stage] else { continue }
                    let lit = rails.contains(stage)
                    let traces = manhattanBundle(from: center, to: dest)
                    for (i, path) in traces.enumerated() {
                        let opacity: Double
                        let w: CGFloat
                        if lit {
                            opacity = 0.95
                            w = i == 0 ? 2.4 : 1.1
                        } else if case .failed = motion {
                            opacity = 0.04
                            w = 0.5
                        } else {
                            opacity = 0.06
                            w = 0.5
                        }
                        ctx.stroke(path, with: .color(stage.color.opacity(opacity)), lineWidth: w)
                        if lit {
                            ctx.stroke(path, with: .color(stage.color.opacity(0.28)), lineWidth: 8)
                        }
                    }

                    if lit && !reduceMotion {
                        let speed = 0.55 + progress * 0.9
                        let r: CGFloat = 4.5 + CGFloat(progress) * 2.5
                        for k in 0..<packetN {
                            let packetT = (t * speed + Double(k) * (1.0 / Double(packetN)))
                                .truncatingRemainder(dividingBy: 1.0)
                            drawPacket(ctx: ctx, from: center, to: dest, t: packetT,
                                       color: stage.color, r: r)
                        }
                    } else if idleCrawl {
                        let cycle = 8.0
                        let slot = (t / cycle).truncatingRemainder(dividingBy: 1.0)
                        let order: [ExploitStage] = [.kernel, .patchset, .daemon, .sandbox]
                        if let idx = order.firstIndex(of: stage) {
                            let a = Double(idx) / 4.0
                            let b = Double(idx + 1) / 4.0
                            if slot >= a && slot < b {
                                let local = (slot - a) / (b - a)
                                drawPacket(ctx: ctx, from: center, to: dest, t: local,
                                           color: stage.color.opacity(0.55), r: 3.2)
                            }
                        }
                    }
                }

                if case .success = motion, !reduceMotion {
                    let pulse = 0.5 + 0.5 * sin(t * 6)
                    var circle = Path()
                    circle.addEllipse(in: CGRect(
                        x: center.x - 40, y: center.y - 40, width: 80, height: 80
                    ))
                    ctx.stroke(circle, with: .color(Color.consoleSuccess.opacity(0.35 * pulse)),
                               lineWidth: 2)
                }
            }
        }
        .allowsHitTesting(false)
    }

    private func drawPacket(ctx: GraphicsContext, from a: CGPoint, to b: CGPoint,
                            t: Double, color: Color, r: CGFloat) {
        let p = pointOnOrthogonal(from: a, to: b, t: t)
        let rect = CGRect(x: p.x - r, y: p.y - r, width: r * 2, height: r * 2)
        ctx.fill(Path(ellipseIn: rect.insetBy(dx: -5, dy: -5)), with: .color(color.opacity(0.28)))
        ctx.fill(Path(ellipseIn: rect), with: .color(color))
        ctx.fill(Path(ellipseIn: rect.insetBy(dx: 1.8, dy: 1.8)), with: .color(.white.opacity(0.85)))
    }

    private func manhattanBundle(from a: CGPoint, to b: CGPoint) -> [Path] {
        let dx = b.x - a.x
        let dy = b.y - a.y
        let clearance: CGFloat = 48
        let start: CGPoint
        if abs(dx) > abs(dy) {
            start = CGPoint(x: a.x + (dx > 0 ? clearance : -clearance), y: a.y)
        } else {
            start = CGPoint(x: a.x, y: a.y + (dy > 0 ? clearance : -clearance))
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

    private func pointOnOrthogonal(from a: CGPoint, to b: CGPoint, t: Double) -> CGPoint {
        let clamped = CGFloat(max(0, min(1, t)))
        return CGPoint(x: a.x + (b.x - a.x) * clamped, y: a.y + (b.y - a.y) * clamped)
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

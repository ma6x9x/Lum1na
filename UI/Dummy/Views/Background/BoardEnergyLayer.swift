import SwiftUI

/// The live layer over the static board, drawn with `TimelineView` + `Canvas`
/// from the precomputed traces: chip halo, run-lit buses, comet pulses flowing
/// into the chip, flickering data bits, chasing edge LEDs and the success surge.
/// Motion Off / Reduce Motion pauses the timeline and draws a static lit frame.
struct BoardEnergyLayer: View {
    let layout: BoardLayout
    let snapshot: BoardSnapshot
    let motion: MotionLevel
    let isDark: Bool

    var body: some View {
        let moving = motion.allowsContinuousMotion
        let interval = motion == .full ? 1.0 / 30.0 : 1.0 / 20.0
        TimelineView(.animation(minimumInterval: interval, paused: !moving)) { timeline in
            Canvas { context, _ in
                draw(in: &context, now: moving ? timeline.date : .distantPast)
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private static let cyan: (Double, Double, Double) = (0.32, 0.82, 1.0)
    private static let violet: (Double, Double, Double) = (0.63, 0.47, 1.0)
    private static let magenta: (Double, Double, Double) = (0.98, 0.24, 0.74)

    private func draw(in context: inout GraphicsContext, now: Date) {
        let t = now.timeIntervalSinceReferenceDate
        let amp = motion.amplitude
        let energy = snapshot.energy
        let hero = layout.hero
        if isDark { context.blendMode = .plusLighter }

        // Chip halo, brightening per completed stage.
        let haloRadius = hero.chipSize * 1.6
        let haloRect = CGRect(x: hero.center.x - haloRadius, y: hero.center.y - haloRadius, width: haloRadius * 2, height: haloRadius * 2)
        context.fill(Path(ellipseIn: haloRect), with: .radialGradient(
            Gradient(colors: [Palette.violet.opacity((isDark ? 0.38 : 0.22) * snapshot.starIntensity), Palette.violet.opacity(0)]),
            center: hero.center, startRadius: hero.chipSize * 0.3, endRadius: haloRadius
        ))

        // Whole-board energize.
        context.stroke(layout.fanPath, with: .color(Color(red: 0.47, green: 0.43, blue: 1).opacity(energy * (isDark ? 0.22 : 0.18))), lineWidth: 1.3)

        drawBuses(in: &context, t: t, amp: amp)
        drawFanPulses(in: &context, t: t, amp: amp, energy: energy)
        if amp > 0 { drawDataBits(in: &context, t: t, energy: energy) }
        if amp >= 1 { drawFieldPulses(in: &context, t: t) }
        drawLEDs(in: &context, t: t, amp: amp)
        drawSurge(in: &context, now: now)
    }

    private func drawBuses(in context: inout GraphicsContext, t: Double, amp: Double) {
        let round = StrokeStyle(lineWidth: 1, lineCap: .round, lineJoin: .round)
        for stage in RunStage.allCases {
            let bus = layout.buses[stage.rawValue]
            let color = stage.color
            let lit = snapshot.isLit(stage.rawValue)
            let active = snapshot.isActive(stage.rawValue)
            if lit || active {
                let k = active && amp > 0 ? 0.65 + 0.35 * sin(t * 7) : 1
                var style = round
                style.lineWidth = 14
                context.stroke(bus.path, with: .color(color.opacity(0.28 * k)), style: style)
                style.lineWidth = 2.2
                context.stroke(bus.path, with: .color(color.opacity(0.9 * k)), style: style)
                style.lineWidth = 0.8
                context.stroke(bus.path, with: .color(.white.opacity(0.5 * k)), style: style)
            } else {
                var style = round
                style.lineWidth = 1.4
                context.stroke(bus.path, with: .color(color.opacity(isDark ? 0.18 : 0.3)), style: style)
            }
            guard active else { continue }
            if amp > 0 {
                // Energy flows from the node into the chip (towards distance 0).
                for q in 0..<3 {
                    let phase = (t * 1.6 + Double(q) / 3).truncatingRemainder(dividingBy: 1)
                    comet(in: &context, trace: bus, at: bus.length * (1 - phase), tail: 34, color: color, head: 3.4)
                }
            } else {
                comet(in: &context, trace: bus, at: bus.length * 0.5, tail: 34, color: color, head: 3.4)
            }
        }
    }

    private func drawFanPulses(in context: inout GraphicsContext, t: Double, amp: Double, energy: Double) {
        let speed = (34 + energy * 150) * (amp > 0 ? 1 : 0)
        for (i, trace) in layout.fans.enumerated() {
            let has = i % 3 == 0 || (energy > 0.5 && i % 3 == 1) || (amp >= 1 && i % 5 == 2 && snapshot.phase != .idle)
            guard has else { continue }
            if amp > 0 && amp < 1 && i % 2 == 1 { continue }
            let rgb = trace.hue < 0.45 ? Self.cyan : trace.hue < 0.8 ? Self.violet : Self.magenta
            let period = Double(trace.length) + 120
            let offset = HexDump.noise(Double(i) * 1.7) * period
            let distance = amp > 0
                ? period - (t * speed + offset).truncatingRemainder(dividingBy: period)
                : HexDump.noise(Double(i)) * Double(trace.length)
            comet(
                in: &context, trace: trace, at: CGFloat(distance), tail: 26 + energy * 30,
                color: Color(red: rgb.0, green: rgb.1, blue: rgb.2), head: 2.3 + energy * 0.8
            )
        }
    }

    private func drawDataBits(in context: inout GraphicsContext, t: Double, energy: Double) {
        let color = isDark ? Palette.phosphor.opacity(0.55 + 0.4 * energy) : Palette.indigo.opacity(0.75)
        var bits = Path()
        let tick = (t * (6 + energy * 10)).rounded(.down)
        for (i, trace) in layout.fans.enumerated() where i % 4 == 1 {
            let base = trace.length * 0.55
            for q in 0..<6 where HexDump.noise(Double(i * 13 + q) + tick) > 0.45 {
                let p = trace.point(at: base + CGFloat(q) * 6)
                bits.addRect(CGRect(x: p.x - 1.2, y: p.y - 1.2, width: 2.4, height: 2.4))
            }
        }
        context.fill(bits, with: .color(color))
    }

    private func drawFieldPulses(in context: inout GraphicsContext, t: Double) {
        for (i, trace) in layout.field.enumerated() where i % 6 == 0 {
            let period = Double(trace.length) + 60
            let d = (t * 40 + HexDump.noise(Double(i)) * period).truncatingRemainder(dividingBy: period)
            comet(in: &context, trace: trace, at: CGFloat(d), tail: -16, color: Palette.indigo, head: 1.6)
        }
    }

    private func drawLEDs(in context: inout GraphicsContext, t: Double, amp: Double) {
        let chase: Double = snapshot.phase == .success ? 22 : snapshot.phase == .running ? 10 : 4
        let ledCore = BoardColors(scheme: isDark ? .dark : .light).ledCore
        for led in layout.leds {
            let raw = (Double(led.index % 16) - t * chase * amp).truncatingRemainder(dividingBy: 16)
            let q = raw < 0 ? raw + 16 : raw
            let v = amp > 0 ? max(0.18, 1 - q / 4) : 0.55
            let glow = led.index % 16 == 0 ? Palette.magenta : Palette.cyan
            let c = led.center
            context.fill(Path(ellipseIn: CGRect(x: c.x - 6, y: c.y - 6, width: 12, height: 12)), with: .color(glow.opacity(0.25 * v)))
            context.fill(Path(CGRect(x: c.x - 1.6, y: c.y - 3.5, width: 3.2, height: 7)), with: .color(ledCore.opacity(v)))
        }
    }

    /// Radial power surge racing outward along every trace after success.
    private func drawSurge(in context: inout GraphicsContext, now: Date) {
        guard let start = snapshot.successDate else { return }
        let age = now.timeIntervalSince(start)
        guard age >= 0 && age < 2.2 else { return }
        let front = CGFloat(age * 520)
        let fade = max(0, 1 - age / 2.2)
        let round = StrokeStyle(lineWidth: 5, lineCap: .round, lineJoin: .round)
        for trace in layout.fans + layout.buses {
            if let head = trace.segment(from: front - 110, to: front) {
                context.stroke(head, with: .color(Palette.cyan.opacity(0.5 * fade)), style: round)
                var core = round
                core.lineWidth = 1.6
                context.stroke(head, with: .color(.white.opacity(0.95 * fade)), style: core)
            }
            if let wake = trace.segment(from: 0, to: front - 110) {
                context.stroke(wake, with: .color(Palette.violet.opacity(0.35 * fade)), lineWidth: 1.6)
            }
        }
        for trace in layout.field {
            let local = front - trace.startDistance
            if let seg = trace.segment(from: local - 60, to: local) {
                context.stroke(seg, with: .color(Palette.phosphorViolet.opacity(0.7 * fade)), lineWidth: 1.4)
            }
        }
    }

    /// A bright head with a fading tail; positive `tail` trails towards the
    /// trace's outer end (pulse moving inward), negative trails the other way.
    private func comet(in context: inout GraphicsContext, trace: BoardTrace, at distance: CGFloat, tail: CGFloat, color: Color, head: CGFloat) {
        guard distance >= 0 && distance <= trace.length else { return }
        for s in 0..<5 {
            let a = distance + tail * CGFloat(s) / 5
            let b = distance + tail * CGFloat(s + 1) / 5
            guard let seg = trace.segment(from: min(a, b), to: max(a, b)) else { continue }
            context.stroke(
                seg,
                with: .color(color.opacity((isDark ? 0.85 : 0.75) * (1 - Double(s) / 5))),
                style: StrokeStyle(lineWidth: head * (1 - CGFloat(s) / 6) * 0.8, lineCap: .round, lineJoin: .round)
            )
        }
        let p = trace.point(at: distance)
        let r = head * 3.2
        context.fill(Path(ellipseIn: CGRect(x: p.x - r, y: p.y - r, width: r * 2, height: r * 2)), with: .radialGradient(
            Gradient(colors: [color.opacity(0.9), color.opacity(0)]), center: p, startRadius: 0, endRadius: r
        ))
        let core = head * 0.55
        context.fill(Path(ellipseIn: CGRect(x: p.x - core, y: p.y - core, width: core * 2, height: core * 2)), with: .color(isDark ? .white.opacity(0.95) : color))
    }
}

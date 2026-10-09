import SwiftUI

/// Deterministic, procedurally generated PCB: chip fan-out traces radiating to
/// the edges, four main buses to the stage nodes, IC footprints, random
/// orthogonal/45° field traces, vias, pads, edge LEDs and connector fingers.
/// Built once per size (cheap, < 10 ms) and drawn from precomputed paths.
struct BoardLayout {
    struct Via { var center: CGPoint; var radius: CGFloat }
    struct Leg { var origin: CGPoint; var normal: CGVector }
    struct LED { var center: CGPoint; var index: Int }

    let size: CGSize
    let hero: HeroLayout
    private(set) var fans: [BoardTrace] = []
    private(set) var buses: [BoardTrace] = []
    private(set) var field: [BoardTrace] = []
    private(set) var vias: [Via] = []
    private(set) var pads: [CGPoint] = []
    private(set) var ics: [CGRect] = []
    private(set) var legs: [Leg] = []
    private(set) var leds: [LED] = []
    private(set) var fingers: [CGRect] = []
    /// All fan traces merged into one path for cheap whole-board strokes.
    private(set) var fanPath = Path()
    private(set) var fieldPath = Path()

    init(size: CGSize, hero: HeroLayout, seed: UInt32 = 1337) {
        self.size = size
        self.hero = hero
        var rng = SeededGenerator(seed: seed)
        var grid = OccupancyGrid(size: size, cell: 6)
        build(rng: &rng, grid: &grid)
    }

    // MARK: - Generation

    private mutating func build(rng: inout SeededGenerator, grid: inout OccupancyGrid) {
        let w = size.width
        let h = size.height
        let c = hero.center
        let half = hero.chipSize / 2
        let legLength: CGFloat = 7
        let pinCount = 13
        let span = hero.chipSize * 0.8

        // Keep-outs: chip and nodes.
        grid.fill(CGRect(x: c.x - half - 14, y: c.y - half - 14, width: hero.chipSize + 28, height: hero.chipSize + 28))
        for node in hero.nodeCenters {
            grid.fill(CGRect(x: node.x - 36, y: node.y - 36, width: 72, height: 80))
        }

        // Fan-out traces from every pin, bending 45° outward, then straight to the edge.
        let normals: [CGVector] = [CGVector(dx: 1, dy: 0), CGVector(dx: -1, dy: 0), CGVector(dx: 0, dy: 1), CGVector(dx: 0, dy: -1)]
        for n in normals {
            let t = CGVector(dx: -n.dy, dy: n.dx)
            for k in 0..<pinCount {
                let o = -span / 2 + span * CGFloat(k) / CGFloat(pinCount - 1)
                let ao = abs(o)
                let sg: CGFloat = o == 0 ? 0 : (o > 0 ? 1 : -1)
                legs.append(Leg(origin: CGPoint(x: c.x + n.dx * half + t.dx * o, y: c.y + n.dy * half + t.dy * o), normal: n))
                let p0 = CGPoint(x: c.x + n.dx * (half + legLength) + t.dx * o, y: c.y + n.dy * (half + legLength) + t.dy * o)
                let a = 6 + (span / 2 - ao) * 0.42
                let p1 = CGPoint(x: p0.x + n.dx * a, y: p0.y + n.dy * a)
                let d = ao * 1.55
                let p2 = CGPoint(x: p1.x + (n.dx + t.dx * sg) * d, y: p1.y + (n.dy + t.dy * sg) * d)
                let far: CGFloat = n.dx > 0 ? w - p2.x : n.dx < 0 ? p2.x : n.dy > 0 ? h - p2.y : p2.y
                var ext = far + 6
                var endsInVia = false
                if rng.unit() < 0.3 {
                    ext = far * (0.3 + rng.unit() * 0.45)
                    endsInVia = true
                }
                let p3 = CGPoint(x: p2.x + n.dx * ext, y: p2.y + n.dy * ext)
                let points = d > 0.5 ? [p0, p1, p2, p3] : [p0, p1, p3]
                fans.append(BoardTrace(points: points, hue: rng.unit()))
                for i in 1..<points.count { grid.markSegment(points[i - 1], points[i], pad: 3) }
                if endsInVia { vias.append(Via(center: p3, radius: 2.6)) }
            }
        }

        // Main buses: chip corner → 45° → stage node.
        for stage in RunStage.allCases {
            let node = hero.nodeCenters[stage.rawValue]
            let sx = CGFloat(stage.corner.x)
            let sy = CGFloat(stage.corner.y)
            let c0 = CGPoint(x: c.x + sx * (half - 4), y: c.y + sy * (half - 4))
            let dist = abs(node.y - c0.y)
            let p1 = CGPoint(x: c0.x + sx * dist, y: node.y)
            buses.append(BoardTrace(points: [c0, p1, node]))
        }

        // IC footprints in free space.
        var tries = 0
        while ics.count < 14 && tries < 600 {
            tries += 1
            let iw = 18 + CGFloat(Int(rng.unit() * 4)) * 6
            let ih = 12 + CGFloat(Int(rng.unit() * 3)) * 4
            let x = (rng.unit() * Double(w - iw - 30) / 3).rounded() * 3 + 15
            let y = (rng.unit() * Double(h - ih - 30) / 3).rounded() * 3 + 15
            let rect = CGRect(x: x, y: y, width: iw, height: ih)
            guard grid.isFree(rect.insetBy(dx: -10, dy: -10)) else { continue }
            grid.fill(rect.insetBy(dx: -6, dy: -6))
            ics.append(rect)
        }

        // Field traces: short seeded walks (orthogonal + 45°), many leaving IC pins.
        let dirs: [CGVector] = [
            CGVector(dx: 1, dy: 0), CGVector(dx: -1, dy: 0), CGVector(dx: 0, dy: 1), CGVector(dx: 0, dy: -1),
            CGVector(dx: 1, dy: 1), CGVector(dx: 1, dy: -1), CGVector(dx: -1, dy: 1), CGVector(dx: -1, dy: -1)
        ]
        var made = 0
        tries = 0
        while made < 150 && tries < 4000 {
            tries += 1
            let start: CGPoint
            var dir: Int
            if rng.unit() < 0.5, !ics.isEmpty {
                let ic = ics[min(Int(rng.unit() * Double(ics.count)), ics.count - 1)]
                let top = rng.unit() < 0.5
                let px = ic.minX + 4 + CGFloat(Int(rng.unit() * Double((ic.width - 4) / 6))) * 6
                start = CGPoint(x: px, y: top ? ic.minY - 6 : ic.maxY + 6)
                dir = top ? 3 : 2
            } else {
                start = CGPoint(x: (rng.unit() * Double(w) / 6).rounded() * 6, y: (rng.unit() * Double(h) / 6).rounded() * 6)
                dir = Int(rng.unit() * 4) % 4
            }
            guard !grid.isOccupied(start) else { continue }
            var points = [start]
            var current = start
            let segments = 2 + Int(rng.unit() * 4)
            for _ in 0..<segments {
                let v = dirs[dir]
                let steps = 2 + Int(rng.unit() * 7)
                let stride: CGFloat = 6
                var blocked = false
                var next = current
                for q in 1...steps {
                    let p = CGPoint(x: current.x + v.dx * CGFloat(q) * stride, y: current.y + v.dy * CGFloat(q) * stride)
                    if grid.isOccupied(p) { blocked = true; break }
                    next = p
                }
                if next != current { points.append(next); current = next }
                if blocked { break }
                let turns: [Int] = dir < 2 ? [4, 5, 2, 3] : dir < 4 ? [4, 6, 0, 1] : [0, 1, 2, 3]
                if rng.unit() < 0.6 { dir = turns[min(Int(rng.unit() * Double(turns.count)), turns.count - 1)] }
            }
            guard points.count > 1 else { continue }
            var trace = BoardTrace(points: points, hue: rng.unit())
            guard trace.length >= 18 else { continue }
            for i in 1..<points.count { grid.markSegment(points[i - 1], points[i], pad: 0) }
            trace.startDistance = hypot(start.x - c.x, start.y - c.y)
            field.append(trace)
            made += 1
            if let end = points.last {
                if rng.unit() < 0.55 { vias.append(Via(center: end, radius: 2.2)) } else { pads.append(end) }
            }
        }

        // Scattered vias.
        for _ in 0..<70 {
            let p = CGPoint(x: (rng.unit() * Double(w) / 6).rounded() * 6, y: (rng.unit() * Double(h) / 6).rounded() * 6)
            if !grid.isOccupied(p) {
                vias.append(Via(center: p, radius: 1.6))
                grid.mark(p)
            }
        }

        // Edge LED columns along the hero band, connector fingers below it and on top.
        let band = hero.bounds
        for i in 0..<16 {
            let y = band.minY + 14 + CGFloat(i) * ((band.height - 28) / 15)
            leds.append(LED(center: CGPoint(x: 6, y: y), index: i))
            leds.append(LED(center: CGPoint(x: w - 6, y: y), index: i + 16))
        }
        var fy = band.maxY + 20
        while fy < h - 10 {
            fingers.append(CGRect(x: 0, y: fy, width: 4, height: 5))
            fingers.append(CGRect(x: w - 4, y: fy, width: 4, height: 5))
            fy += 9
        }
        var fx: CGFloat = 24
        while fx < w - 24 {
            fingers.append(CGRect(x: fx, y: -1, width: 4, height: 5))
            fx += 9
        }

        for trace in fans { fanPath.addPath(trace.path) }
        for trace in field { fieldPath.addPath(trace.path) }
    }
}

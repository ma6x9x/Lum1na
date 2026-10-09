import SwiftUI

/// One precomputed PCB trace: a polyline with cumulative lengths so pulses can
/// be placed and trimmed along it cheaply every frame.
struct BoardTrace {
    let points: [CGPoint]
    let cumulative: [CGFloat]
    let path: Path
    /// 0…1 seeded value used to vary pulse colour/phase.
    var hue: Double = 0
    /// Distance of the first point from the chip centre (field traces' surge offset).
    var startDistance: CGFloat = 0

    var length: CGFloat { cumulative.last ?? 0 }

    init(points: [CGPoint], hue: Double = 0) {
        self.points = points
        self.hue = hue
        var cum: [CGFloat] = [0]
        var path = Path()
        if let first = points.first { path.move(to: first) }
        for i in 1..<max(points.count, 1) {
            cum.append(cum[i - 1] + hypot(points[i].x - points[i - 1].x, points[i].y - points[i - 1].y))
            path.addLine(to: points[i])
        }
        cumulative = cum
        self.path = path
    }

    /// Point at a distance along the trace (clamped).
    func point(at distance: CGFloat) -> CGPoint {
        guard points.count > 1 else { return points.first ?? .zero }
        let d = min(max(distance, 0), length)
        var i = 1
        while i < cumulative.count - 1 && cumulative[i] < d { i += 1 }
        let span = max(cumulative[i] - cumulative[i - 1], 0.0001)
        let k = (d - cumulative[i - 1]) / span
        let a = points[i - 1]
        let b = points[i]
        return CGPoint(x: a.x + (b.x - a.x) * k, y: a.y + (b.y - a.y) * k)
    }

    /// The sub-polyline between two distances, or `nil` if empty.
    func segment(from start: CGFloat, to end: CGFloat) -> Path? {
        let d0 = max(0, start)
        let d1 = min(length, end)
        guard d1 > d0 else { return nil }
        var path = Path()
        path.move(to: point(at: d0))
        for i in 1..<points.count where cumulative[i] > d0 && cumulative[i] < d1 {
            path.addLine(to: points[i])
        }
        path.addLine(to: point(at: d1))
        return path
    }
}

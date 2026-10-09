import CoreGraphics

/// Coarse occupancy grid that keeps generated traces and ICs from overlapping.
struct OccupancyGrid {
    private let cell: CGFloat
    private let columns: Int
    private let rows: Int
    private var cells: [Bool]

    init(size: CGSize, cell: CGFloat) {
        self.cell = cell
        columns = max(Int((size.width / cell).rounded(.up)), 1)
        rows = max(Int((size.height / cell).rounded(.up)), 1)
        cells = Array(repeating: false, count: columns * rows)
    }

    private func index(_ p: CGPoint) -> Int? {
        let i = Int((p.x / cell).rounded(.down))
        let j = Int((p.y / cell).rounded(.down))
        guard i >= 0, j >= 0, i < columns, j < rows else { return nil }
        return j * columns + i
    }

    /// Out-of-bounds points count as occupied.
    func isOccupied(_ p: CGPoint) -> Bool {
        guard let idx = index(p) else { return true }
        return cells[idx]
    }

    func isFree(_ rect: CGRect) -> Bool {
        var x = rect.minX
        while x <= rect.maxX {
            var y = rect.minY
            while y <= rect.maxY {
                if isOccupied(CGPoint(x: x, y: y)) { return false }
                y += cell
            }
            x += cell
        }
        return true
    }

    mutating func mark(_ p: CGPoint) {
        if let idx = index(p) { cells[idx] = true }
    }

    mutating func fill(_ rect: CGRect) {
        var x = rect.minX
        while x <= rect.maxX {
            var y = rect.minY
            while y <= rect.maxY {
                mark(CGPoint(x: x, y: y))
                y += 3
            }
            x += 3
        }
    }

    mutating func markSegment(_ a: CGPoint, _ b: CGPoint, pad: CGFloat) {
        let length = hypot(b.x - a.x, b.y - a.y)
        let steps = max(1, Int((length / 3).rounded(.up)))
        for s in 0...steps {
            let k = CGFloat(s) / CGFloat(steps)
            let p = CGPoint(x: a.x + (b.x - a.x) * k, y: a.y + (b.y - a.y) * k)
            if pad <= 0 {
                mark(p)
            } else {
                var ox = -pad
                while ox <= pad {
                    var oy = -pad
                    while oy <= pad {
                        mark(CGPoint(x: p.x + ox, y: p.y + oy))
                        oy += cell
                    }
                    ox += cell
                }
            }
        }
    }
}

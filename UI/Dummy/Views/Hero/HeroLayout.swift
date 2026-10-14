import CoreGraphics

/// Geometry of the hero: chip centre/size and the four stage-node centres.
/// The same formula positions the SwiftUI chip/nodes and the board's buses, so
/// traces land exactly on the views (mirrors `heroLayout` in the HTML preview).
///
/// Optical notes: the chip centre sits above the band's midline so the glass
/// die reads as "risen" against the header, and the nodes sit slightly
/// outside/above the pure-corner positions so their labels clear the board
/// edges while the icons still catch the bus ends.
struct HeroLayout: Equatable {
    var center: CGPoint
    var chipSize: CGFloat
    var nodeSize: CGFloat
    var nodeCenters: [CGPoint]
    var bounds: CGRect

    init(in rect: CGRect) {
        bounds = rect
        // Must include rect.minY. The board passes the hero's offset frame;
        // using height alone drew the buses at the top of the screen while
        // the SwiftUI chip sat under the header.
        // Composition anchor: 0.48 sits the chip (and every board feature
        // derived from it — buses, fans, halo, gradient centre) lower in the
        // band so the board no longer reads top-heavy against the header
        // (2026-10-14 UI pass 2). SwiftUI chip and board share this formula,
        // so alignment is invariant under the shift.
        center = CGPoint(x: rect.midX, y: rect.minY + rect.height * 0.48)
        chipSize = (min(rect.width, rect.height) * 0.40).rounded()
        nodeSize = 58
        // Pads sit slightly outward vs the old 0.36/0.29 spread so the corner
        // labels clear the board edges (2026-10-14). Vertical spread relaxed
        // 0.315 -> 0.30 when the composition moved down, keeping the bottom
        // pad labels clear of the console card.
        let dx = rect.width * 0.375
        let dy = rect.height * 0.30
        let c = center
        nodeCenters = RunStage.allCases.map { stage in
            CGPoint(x: c.x + CGFloat(stage.corner.x) * dx, y: c.y + CGFloat(stage.corner.y) * dy)
        }
    }
}

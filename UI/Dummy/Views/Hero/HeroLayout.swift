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
        center = CGPoint(x: rect.midX, y: rect.height * 0.455)
        chipSize = (min(rect.width, rect.height) * 0.40).rounded()
        nodeSize = 58
        let dx = rect.width * 0.36
        let dy = rect.height * 0.29
        let c = center
        nodeCenters = RunStage.allCases.map { stage in
            CGPoint(x: c.x + CGFloat(stage.corner.x) * dx, y: c.y + CGFloat(stage.corner.y) * dy)
        }
    }
}

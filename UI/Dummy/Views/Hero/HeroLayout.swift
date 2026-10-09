import CoreGraphics

/// Geometry of the hero: chip centre/size and the four stage-node centres.
/// The same formula positions the SwiftUI chip/nodes and the board's buses, so
/// traces land exactly on the views (mirrors `heroLayout` in the HTML preview).
struct HeroLayout: Equatable {
    var center: CGPoint
    var chipSize: CGFloat
    var nodeSize: CGFloat
    var nodeCenters: [CGPoint]
    var bounds: CGRect

    init(in rect: CGRect) {
        bounds = rect
        center = CGPoint(x: rect.midX, y: rect.midY)
        chipSize = (min(rect.width, rect.height) * 0.40).rounded()
        nodeSize = 58
        let dx = rect.width * 0.335
        let dy = rect.height * 0.33
        let c = center
        nodeCenters = RunStage.allCases.map { stage in
            CGPoint(x: c.x + CGFloat(stage.corner.x) * dx, y: c.y + CGFloat(stage.corner.y) * dy)
        }
    }
}

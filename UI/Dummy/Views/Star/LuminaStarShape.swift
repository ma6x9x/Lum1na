import SwiftUI

/// Vector recreation of the Lum1na logo: a concave four-point "sparkle" star
/// with long vertical points and slightly shorter horizontal points. Drawing it
/// as a `Shape` (rather than the bitmap) lets it animate crisply at any size.
///
/// Each edge is a quadratic curve whose control point sits near the centre,
/// pinching the arms inward for the concave look.
struct LuminaStarShape: Shape {
    /// Vertical arm half-length as a fraction of the frame (0…0.5).
    var verticalExtent: CGFloat = 0.5
    /// Horizontal arm half-length as a fraction of the frame.
    var horizontalExtent: CGFloat = 0.42
    /// How far the waist control points sit from the centre along each diagonal
    /// (0 = exactly centre → the sharpest concave arms).
    var waist: CGFloat = 0.0

    var animatableData: AnimatablePair<CGFloat, CGFloat> {
        get { AnimatablePair(verticalExtent, horizontalExtent) }
        set {
            verticalExtent = newValue.first
            horizontalExtent = newValue.second
        }
    }

    func path(in rect: CGRect) -> Path {
        let w = rect.width
        let h = rect.height
        func pt(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: rect.minX + x * w, y: rect.minY + y * h)
        }

        let top = pt(0.5, 0.5 - verticalExtent)
        let right = pt(0.5 + horizontalExtent, 0.5)
        let bottom = pt(0.5, 0.5 + verticalExtent)
        let left = pt(0.5 - horizontalExtent, 0.5)

        // Waist control points pull toward the centre along each diagonal.
        func ctrl(_ dx: CGFloat, _ dy: CGFloat) -> CGPoint {
            pt(0.5 + dx * waist, 0.5 + dy * waist)
        }

        var path = Path()
        path.move(to: top)
        path.addQuadCurve(to: right, control: ctrl(0.5, -0.5))
        path.addQuadCurve(to: bottom, control: ctrl(0.5, 0.5))
        path.addQuadCurve(to: left, control: ctrl(-0.5, 0.5))
        path.addQuadCurve(to: top, control: ctrl(-0.5, -0.5))
        path.closeSubpath()
        return path
    }
}

#Preview("Star shape") {
    LuminaStarShape()
        .fill(Palette.starGradient)
        .frame(width: 200, height: 200)
        .padding()
        .background(.black)
}

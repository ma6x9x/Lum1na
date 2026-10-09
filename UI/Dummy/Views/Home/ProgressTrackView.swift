import SwiftUI

/// A rounded progress track with a gradient fill, used inside the progress capsule.
struct ProgressTrackView: View {
    var progress: Double
    var motion: MotionLevel

    var body: some View {
        GeometryReader { proxy in
            let width = proxy.size.width
            ZStack(alignment: .leading) {
                Capsule().fill(.white.opacity(0.12))
                Capsule()
                    .fill(Palette.starGradient)
                    .frame(width: max(6, width * progress))
                    .shadow(color: Palette.violet.opacity(0.6), radius: 5)
                    .animation(Motion.adaptive(Motion.smooth, motion: motion), value: progress)
            }
        }
        .frame(height: 6)
        .accessibilityHidden(true)
    }
}

#Preview("Track") {
    ProgressTrackView(progress: 0.6, motion: .full)
        .frame(width: 200)
        .padding()
        .background(.black)
}

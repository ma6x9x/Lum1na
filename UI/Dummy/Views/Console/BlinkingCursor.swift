import SwiftUI

/// Block cursor that blinks at ~1 Hz; solid when motion is off.
struct BlinkingCursor: View {
    @Environment(\.luminaMotion) private var motion

    var body: some View {
        if motion.allowsContinuousMotion {
            TimelineView(.periodic(from: .now, by: 0.53)) { timeline in
                let on = Int(timeline.date.timeIntervalSinceReferenceDate / 0.53).isMultiple(of: 2)
                block.opacity(on ? 1 : 0)
            }
        } else {
            block
        }
    }

    private var block: some View {
        Rectangle()
            .fill(Palette.phosphor)
            .frame(width: 7, height: 12)
            .shadow(color: Palette.cyan, radius: 3)
            .accessibilityHidden(true)
    }
}

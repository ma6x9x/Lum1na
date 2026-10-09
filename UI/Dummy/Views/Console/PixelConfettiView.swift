import SwiftUI

/// Pixel spark confetti that bursts for ~2.6 s after success. Snapped to a
/// pixel grid for the retro look; uses a finite explicit schedule so it stops
/// redrawing when done. Hidden when motion is reduced or off.
struct PixelConfettiView: View {
    var successDate: Date?

    @Environment(\.luminaMotion) private var motion

    private static let duration: TimeInterval = 2.6
    private static let colors: [Color] = [Palette.magenta, Palette.violet, Palette.cyan, .white, Palette.success, Color(red: 1, green: 0.81, blue: 0.3)]

    var body: some View {
        if let successDate, motion.allowsContinuousMotion, Date.now < successDate.addingTimeInterval(Self.duration) {
            TimelineView(.explicit(Self.frames(from: successDate))) { timeline in
                Canvas { context, size in
                    draw(in: &context, size: size, age: timeline.date.timeIntervalSince(successDate))
                }
            }
            .allowsHitTesting(false)
            .accessibilityHidden(true)
        }
    }

    private static func frames(from start: Date) -> [Date] {
        let begin = max(start, .now)
        let end = start.addingTimeInterval(duration)
        return Array(stride(from: begin.timeIntervalSinceReferenceDate, through: end.timeIntervalSinceReferenceDate, by: 1.0 / 30.0))
            .map { Date(timeIntervalSinceReferenceDate: $0) }
    }

    private func draw(in context: inout GraphicsContext, size: CGSize, age: TimeInterval) {
        guard age >= 0 && age < Self.duration - 0.05 else { return }
        for i in 0..<70 {
            let n = Double(i)
            let angle = HexDump.noise(n * 3.1) * 2 * .pi
            let speed = 60 + HexDump.noise(n * 7.7) * 160
            let x0 = size.width * (0.3 + HexDump.noise(n * 1.3) * 0.4)
            let y0 = size.height * 0.45
            let x = x0 + cos(angle) * speed * age
            let y = y0 + sin(angle) * speed * age * 0.7 + 90 * age * age
            let alpha = max(0, 1 - age / 2.4) * (0.6 + 0.4 * sin(age * 20 + n))
            let s: CGFloat = HexDump.noise(n * 5.5) > 0.7 ? 4 : 3
            let rect = CGRect(x: (x / s).rounded() * s, y: (y / s).rounded() * s, width: s, height: s)
            context.fill(Path(rect), with: .color(Self.colors[i % Self.colors.count].opacity(alpha)))
        }
    }
}

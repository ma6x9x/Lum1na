import SwiftUI

/// Per-stage dithered progress bar filling with `░▒▓█` pixel cells. Reads the
/// model's progress directly so only this row re-renders on each tick.
struct StageMeterView: View {
    let stage: RunStage
    var style: ConsoleStyle
    var showTimestamp: Bool
    var timestamp: String

    @Environment(LuminaRunModel.self) private var model

    private let cells = 22
    private static let bayer: [[Double]] = [[0, 2], [3, 1]]

    private var fraction: Double {
        min(max(model.progress * Double(RunStage.allCases.count) - Double(stage.rawValue), 0), 1)
    }

    var body: some View {
        HStack(spacing: 6) {
            if showTimestamp {
                Text(timestamp).foregroundStyle(Palette.phosphor.opacity(0.38))
            }
            Text(stage.title.uppercased().padding(toLength: 8, withPad: " ", startingAt: 0))
                .foregroundStyle(stage.color)
            Canvas { context, size in
                draw(in: &context, size: size)
            }
            .frame(width: CGFloat(cells) * 6, height: 6)
            .shadow(color: style == .crt ? stage.color.opacity(0.8) : .clear, radius: 3)
            Text("\(Int((fraction * 100).rounded()))%")
                .monospacedDigit()
                .frame(minWidth: 30, alignment: .trailing)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(stage.title) \(Int((fraction * 100).rounded())) percent")
    }

    private func draw(in context: inout GraphicsContext, size: CGSize) {
        let cell = size.width / CGFloat(cells)
        let filled = fraction * Double(cells)
        var solid = Path()
        var empty = Path()
        for k in 0..<cells {
            let d = filled - Double(k)
            let level: Double = d >= 3 ? 1 : d >= 2 ? 0.75 : d >= 1 ? 0.5 : d > 0 ? 0.25 : 0
            let x = CGFloat(k) * cell
            let s = cell - 1
            if level == 0 {
                empty.addRect(CGRect(x: x + s / 2 - 0.6, y: size.height / 2 - 0.6, width: 1.2, height: 1.2))
            } else if level >= 1 {
                solid.addRect(CGRect(x: x, y: 0, width: s, height: s))
            } else {
                let h = s / 2
                for i in 0..<2 {
                    for j in 0..<2 where (Self.bayer[i][j] + 0.5) / 4 < level {
                        solid.addRect(CGRect(x: x + CGFloat(j) * h, y: CGFloat(i) * h, width: h - 0.3, height: h - 0.3))
                    }
                }
            }
        }
        context.fill(empty, with: .color(Palette.phosphor.opacity(0.16)))
        context.fill(solid, with: .color(stage.color))
    }
}

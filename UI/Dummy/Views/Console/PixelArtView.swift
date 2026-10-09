import SwiftUI

/// Renders block-character art as a crisp pixel grid in one `Canvas`:
/// `█` solid, `▓▒░` as 2×2 ordered (Bayer) dither, letter bodies in a
/// phosphor ramp, the accent "1" and star in the brand gradient, a white core.
/// Rows reveal top-down via `revealedRows`; glow adds a phosphor bloom.
struct PixelArtView: View {
    let rows: [String]
    var maxCell: CGFloat = 7
    var revealedRows: Int = .max
    var glow = true
    var isDark = true

    @State private var availableWidth: CGFloat = 0

    private var columns: Int { max(rows.map(\.count).max() ?? 1, 1) }

    var body: some View {
        // Explicit cell size → deterministic height, so stacked logs lay out predictably.
        let cell = availableWidth > 0 ? min(maxCell, availableWidth / CGFloat(columns)) : maxCell
        Canvas { context, _ in
            draw(in: &context, cell: cell)
        }
        .frame(width: CGFloat(columns) * cell, height: CGFloat(rows.count) * cell)
        .shadow(color: glow ? Palette.cyan.opacity(0.55) : .clear, radius: glow ? 4 : 0)
        .frame(maxWidth: .infinity, alignment: .leading)
        .onGeometryChange(for: CGFloat.self) { proxy in
            proxy.size.width
        } action: { width in
            availableWidth = width
        }
        .accessibilityHidden(true)
    }

    private static let bayer: [[Double]] = [[0, 2], [3, 1]]

    private func draw(in context: inout GraphicsContext, cell: CGFloat) {
        let rowCount = rows.count
        let gap = max(0.6, cell * 0.12)
        for (r, row) in rows.enumerated() where r < revealedRows {
            for (c, ch) in row.enumerated() {
                guard ch != " " && ch != "." else { continue }
                let (color, level) = style(for: ch, row: r, column: c, rowCount: rowCount)
                let x = CGFloat(c) * cell
                let y = CGFloat(r) * cell
                let s = cell - gap
                if level >= 1 {
                    context.fill(Path(CGRect(x: x, y: y, width: s, height: s)), with: .color(color))
                } else {
                    let h = s / 2
                    var dots = Path()
                    for i in 0..<2 {
                        for j in 0..<2 where (Self.bayer[i][j] + 0.5) / 4 < level {
                            dots.addRect(CGRect(x: x + CGFloat(j) * h, y: y + CGFloat(i) * h, width: h - 0.3, height: h - 0.3))
                        }
                    }
                    context.fill(dots, with: .color(color))
                }
            }
        }
    }

    private func style(for ch: Character, row r: Int, column c: Int, rowCount: Int) -> (Color, Double) {
        switch ch {
        case "█":
            let color = r < 5
                ? Color.white.mix(with: Palette.cyan, by: min(1, Double(r) / 4))
                : Palette.cyan.mix(with: Color(red: 0.55, green: 0.42, blue: 1), by: Double(r - 5) / 2)
            return (color, 1)
        case "1":
            return (Palette.starRamp(Double(r) / 6), 1)
        case "s":
            return (Palette.starRamp(Double(r + c) / 24), 1)
        case "*":
            return (.white, 1)
        case "▓":
            return (isDark ? Color(red: 0.24, green: 0.16, blue: 0.62) : Color(red: 0.48, green: 0.41, blue: 0.85), 0.5)
        case "▒":
            return (Palette.phosphor, 0.5)
        case "░":
            return (Palette.phosphor, 0.25)
        default:
            return (Palette.phosphor, 1)
        }
    }
}

#Preview("Pixel art") {
    VStack(alignment: .leading, spacing: 16) {
        PixelArtView(rows: PixelArtwork.lumina.rows)
        PixelArtView(rows: PixelArtwork.illuminated.rows, maxCell: 5)
    }
    .padding()
    .background(.black)
}

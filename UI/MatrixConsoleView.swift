import SwiftUI

/// Console that shows real manager lines, with optional symbol-rain that
/// coalesces into a star / Lum1na mark while a run is active — presentation only.
struct MatrixConsoleView: View {
    @ObservedObject private var manager = ExploitManager.shared
    @State private var rainTick: Int = 0

    private let starMark: [String] = [
        "            .            ",
        "           /\\           ",
        "      .___/  \\___.      ",
        "      \\  Lum1na  /      ",
        "       \\  ★★  /       ",
        "      __/      \\__      ",
        "           \\  /           ",
        "            \\/            "
    ]

    var body: some View {
        LiquidGlassCard(cornerRadius: 20) {
            ZStack(alignment: .topLeading) {
                Color.black.opacity(0.55)

                if manager.isRunning {
                    symbolWeave
                        .opacity(0.35)
                        .allowsHitTesting(false)
                }

                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 3) {
                            ForEach(manager.lines) { line in
                                Text(line.text)
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundStyle(line.color)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(line.id)
                            }
                        }
                        .padding(12)
                    }
                    .onChange(of: manager.lines.count) { _ in
                        guard let last = manager.lines.last else { return }
                        withAnimation(.easeOut(duration: 0.12)) {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
            .frame(minHeight: 160)
        }
        .overlay(alignment: .topTrailing) {
            if manager.isRunning {
                Text("weaving")
                    .font(.system(size: 10, weight: .semibold, design: .rounded))
                    .foregroundStyle(Lum1naPalette.ice)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(.ultraThinMaterial, in: Capsule())
                    .padding(10)
            }
        }
        .onReceive(Timer.publish(every: 0.35, on: .main, in: .common).autoconnect()) { _ in
            guard manager.isRunning else { return }
            rainTick &+= 1
        }
        .accessibilityLabel("Session console")
    }

    private var symbolWeave: some View {
        let glyphs = Array("★✦✧*+◇01#@")
        return VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(starMark.enumerated()), id: \.offset) { row, template in
                HStack(spacing: 0) {
                    ForEach(Array(template.enumerated()), id: \.offset) { col, ch in
                        let showMark = !ch.isWhitespace && (rainTick + row + col) % 3 != 0
                        Text(showMark ? String(ch) : String(glyphs[(row * 11 + col + rainTick) % glyphs.count]))
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(
                                ch.isWhitespace
                                    ? Lum1naPalette.rain.opacity(0.12)
                                    : Color.white.opacity(0.55)
                            )
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(12)
    }
}

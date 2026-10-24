import SwiftUI
import UIKit

/// Fullscreen log on the live board: same CRT glass plate as the compact
/// console, filled with every line plus the LUM1NA splash. Hero, PATCH
/// and progress hide; the circuit background stays. Header Done dismisses.
struct ConsolePanelView: View {
    var onClose: () -> Void

    @Environment(LuminaRunModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @Environment(\.luminaMotion) private var motion
    @ObservedObject private var exploits = ExploitManager.shared

    @State private var didCopy = false
    @State private var openedAt = Date.now

    var body: some View {
        CRTTerminalView(style: settings.consoleStyle, cornerRadius: 18) {
            terminal
        }
        .onAppear { openedAt = .now }
        .sensoryFeedback(.success, trigger: didCopy) { _, now in now }
    }

    private var terminal: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text("LUM1NA://TERMINAL")
                    .tracking(1.5)
                    .foregroundStyle(Palette.phosphorViolet)
                Spacer()
                Text(model.isRunning ? "● LIVE" : model.statusText.uppercased())
                    .tracking(1.5)
                    .foregroundStyle(model.phase == .idle ? Palette.phosphorViolet : Palette.success)
                Button(didCopy ? "Copied" : "Copy",
                       systemImage: didCopy ? "checkmark" : "doc.on.doc",
                       action: copyLog)
                    .labelStyle(.iconOnly)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Palette.phosphorViolet)
                    .frame(width: 36, height: 32)
                    .disabled(exploits.lines.isEmpty)
                Button(action: onClose) {
                    Image(systemName: "arrow.down.right.and.arrow.up.left")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Palette.phosphorViolet)
                        .frame(width: 36, height: 32)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Collapse console")
            }
            .font(TerminalFont.font(settings.consoleStyle, size: 15, relativeTo: .caption))
            .dynamicTypeSize(...DynamicTypeSize.xxxLarge)

            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        splash
                        ConsoleLogView(compact: false)
                        Color.clear.frame(height: 1).id(bottomID)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .scrollIndicators(.hidden)
                .onChange(of: exploits.lines.count) {
                    withAnimation(.easeOut(duration: 0.2)) { proxy.scrollTo(bottomID, anchor: .bottom) }
                }
                .onAppear { proxy.scrollTo(bottomID, anchor: .bottom) }
            }
            .overlay {
                PixelConfettiView(successDate: model.successDate)
                    .allowsHitTesting(false)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    @ViewBuilder
    private var splash: some View {
        let rows = PixelArtwork.lumina.rows
        let revealEnd = openedAt.addingTimeInterval(Double(rows.count) * 0.06 + 0.1)
        if motion.allowsContinuousMotion && revealEnd > .now {
            TimelineView(.explicit(Self.splashFrames(from: openedAt, rows: rows.count))) { timeline in
                splashArt(rows: rows, revealed: Int(timeline.date.timeIntervalSince(openedAt) / 0.06) + 1)
            }
        } else {
            splashArt(rows: rows, revealed: rows.count)
        }
    }

    private static func splashFrames(from start: Date, rows: Int) -> [Date] {
        (0...rows + 1).map { start.addingTimeInterval(Double($0) * 0.06) }
    }

    private func splashArt(rows: [String], revealed: Int) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            PixelArtView(rows: rows, maxCell: 7.2, revealedRows: revealed, glow: settings.consoleStyle == .crt)
            Text("guiding-light shell · live console")
                .font(TerminalFont.font(settings.consoleStyle, size: 14, relativeTo: .caption))
                .foregroundStyle(Palette.phosphorViolet.opacity(0.8))
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Lum1na terminal")
    }

    private func copyLog() {
        UIPasteboard.general.string = exploits.lines.map(\.formatted).joined(separator: "\n")
        withAnimation { didCopy = true }
        Task {
            try? await Task.sleep(for: .seconds(2))
            withAnimation { didCopy = false }
        }
    }

    private let bottomID = "console-bottom"
}

#Preview("Console panel") {
    ZStack {
        Color(red: 0.02, green: 0.024, blue: 0.06)
        ConsolePanelView(onClose: {})
            .padding(18)
    }
    .environment(LuminaRunModel())
    .environment(AppSettings())
    .environment(\.luminaMotion, MotionLevel.full)
    .preferredColorScheme(.dark)
}

import SwiftUI
import UIKit

/// Full console sheet: a tall CRT terminal that types a LUM1NA splash banner
/// line by line when it opens, then shows every log entry (auto-scrolling).
/// Copy places the plain-text log on the local clipboard.
struct ConsoleSheetView: View {
    @Environment(LuminaRunModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @Environment(\.dismiss) private var dismiss
    @Environment(\.luminaMotion) private var motion
    @ObservedObject private var exploits = ExploitManager.shared

    @State private var didCopy = false
    @State private var openedAt = Date.now

    var body: some View {
        NavigationStack {
            ZStack {
                CircuitBoardView(animated: false)
                CRTTerminalView(style: settings.consoleStyle, cornerRadius: 18) {
                    terminal
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 12)
            }
            .navigationTitle("Logs")
            .toolbarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .topBarLeading) {
                    Button(didCopy ? "Copied" : "Copy", systemImage: didCopy ? "checkmark" : "doc.on.doc", action: copyLog)
                        .disabled(exploits.lines.isEmpty)
                }
            }
            .sensoryFeedback(.success, trigger: didCopy) { _, now in now }
        }
        .onAppear { openedAt = .now }
    }

    private var terminal: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("LUM1NA://TERMINAL")
                    .foregroundStyle(Palette.phosphorViolet)
                Spacer()
                Text(model.isRunning ? "● LIVE" : model.statusText.uppercased())
                    .foregroundStyle(Palette.success)
            }
            .font(TerminalFont.font(settings.consoleStyle, size: 15, relativeTo: .caption))
            .tracking(1.5)

            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        splash
                        ConsoleLogView(compact: false)
                        Color.clear.frame(height: 1).id(bottomID)
                    }
                }
                .scrollIndicators(.hidden)
                .onChange(of: exploits.lines.count) {
                    withAnimation(.easeOut(duration: 0.2)) { proxy.scrollTo(bottomID, anchor: .bottom) }
                }
                .onAppear { proxy.scrollTo(bottomID, anchor: .bottom) }
            }
            .overlay {
                PixelConfettiView(successDate: model.successDate)
            }
        }
        .padding(12)
    }

    /// Splash banner revealed row by row when the sheet opens.
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

#Preview("Console sheet – Dark") {
    ConsoleSheetView()
        .environment(LuminaRunModel())
        .environment(AppSettings())
        .environment(\.luminaMotion, MotionLevel.full)
        .preferredColorScheme(.dark)
}

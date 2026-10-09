import SwiftUI

/// Real probe log inside the CRT chrome. One monospaced line per
/// `ConsoleLine.formatted` entry, colored by level. Typewriter/decode stays
/// display-only; disk TAP is untouched.
struct ConsoleLogView: View {
    var compact: Bool

    @ObservedObject private var manager = ExploitManager.shared
    @StateObject private var performer = ConsolePerformer()
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        let lines = displayLines
        VStack(alignment: .leading, spacing: compact ? 1 : 2) {
            if lines.isEmpty {
                Text("awaiting ignition")
                    .foregroundStyle(Palette.phosphorViolet)
            }
            ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                Text(line)
                    .foregroundStyle(color(for: line))
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .font(.system(size: compact ? 11 : 13, design: .monospaced))
        .textSelection(.enabled)
        .onAppear {
            performer.reduceMotion = reduceMotion
            performer.sync(from: manager.lines)
        }
        .onChange(of: manager.lines.count) {
            performer.reduceMotion = reduceMotion
            performer.sync(from: manager.lines)
        }
        .onChange(of: reduceMotion) {
            performer.reduceMotion = reduceMotion
        }
    }

    private var displayLines: [String] {
        let played = performer.finished + (performer.draft.isEmpty ? [] : [performer.draft])
        let source = played.isEmpty ? manager.lines.map(\.formatted) : played
        return compact ? Array(source.suffix(14)) : source
    }

    private func color(for line: String) -> Color {
        if line.contains("[+]") { return ConsoleLine.LogLevel.success.color }
        if line.contains("[!]") { return ConsoleLine.LogLevel.warning.color }
        if line.contains("[-]") { return ConsoleLine.LogLevel.error.color }
        if line.contains("[*]") || line.contains("[KERN]") || line.contains("===") {
            return ConsoleLine.LogLevel.info.color
        }
        return Palette.phosphor
    }
}

import SwiftUI

/// One console entry. Animated rows (glitch reveal, spinner, scrolling hex,
/// banner row reveal) get a `TimelineView`; a finite explicit schedule is
/// used for reveals so finished rows stop redrawing. Reduce Motion / Motion
/// Off renders the final state immediately with no glitch or spinner motion.
struct ConsoleRowView: View {
    let entry: LogEntry
    var style: ConsoleStyle
    var showTimestamp: Bool
    var artCell: CGFloat

    @Environment(\.luminaMotion) private var motion
    @Environment(\.colorScheme) private var scheme

    private static let spinner = Array("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    private static let artRowInterval: TimeInterval = 0.045

    var body: some View {
        if motion.allowsContinuousMotion && isContinuous {
            TimelineView(.animation(minimumInterval: 1.0 / 30.0)) { timeline in
                row(now: timeline.date)
            }
        } else if motion.allowsContinuousMotion, let end = revealEnd, end > .now {
            TimelineView(.explicit(Self.frames(until: end))) { timeline in
                row(now: timeline.date)
            }
        } else {
            row(now: .distantFuture)
        }
    }

    // MARK: - Clock

    private var isContinuous: Bool {
        switch entry.kind {
        case .line(let tag): tag == .busy
        case .hexDump: !entry.isSettled
        default: false
        }
    }

    private var revealEnd: Date? {
        switch entry.kind {
        case .line:
            entry.createdAt.addingTimeInterval(ScrambleText.duration(for: entry.text) + 0.05)
        case .header(let stage):
            entry.createdAt.addingTimeInterval(ScrambleText.duration(for: Self.headerLabel(stage)) + 0.05)
        case .art(let artwork):
            entry.createdAt.addingTimeInterval(Double(artwork.rows.count) * Self.artRowInterval + 0.05)
        default:
            nil
        }
    }

    private static func frames(until end: Date) -> [Date] {
        let start = Date.now
        var dates: [Date] = []
        var t = start
        while t < end {
            dates.append(t)
            t = t.addingTimeInterval(1.0 / 30.0)
        }
        dates.append(end.addingTimeInterval(0.02))
        return dates
    }

    // MARK: - Content

    @ViewBuilder
    private func row(now: Date) -> some View {
        let age = now.timeIntervalSince(entry.createdAt)
        switch entry.kind {
        case .line(let tag):
            lineRow(tag: tag, age: age)
        case .header(let stage):
            headerRow(stage: stage, age: age)
        case .art(let artwork):
            PixelArtView(
                rows: artwork.rows,
                maxCell: artCell,
                revealedRows: max(1, Int(age / Self.artRowInterval) + 1),
                glow: style == .crt,
                isDark: scheme == .dark
            )
            .padding(.vertical, 2)
            .accessibilityElement()
            .accessibilityLabel(artwork == .lumina ? "Lum1na banner" : "Illuminated banner")
        case .hexDump(let seed):
            let offset = entry.isSettled ? 40 + seed : Int(max(age, 0) / 0.07) + seed
            Text(HexDump.rows(seed: seed, offset: offset).joined(separator: "\n"))
                .foregroundStyle(Palette.phosphorViolet.opacity(0.75))
                .lineLimit(3)
                .accessibilityHidden(true)
        case .meter(let stage):
            StageMeterView(stage: stage, style: style, showTimestamp: showTimestamp, timestamp: entry.timestamp)
        }
    }

    private func lineRow(tag: LogTag, age: TimeInterval) -> some View {
        let scrambled = ScrambleText.render(entry.text, age: age, seed: entry.text.count)
        let spinning = motion.allowsContinuousMotion
        return HStack(spacing: 6) {
            timestamp
            TagChipView(tag: tag, style: style)
            if tag == .busy {
                Text(spinning ? String(Self.spinner[Int(max(age, 0) / 0.08) % Self.spinner.count]) : "…")
                    .foregroundStyle(.white)
            }
            Text("\(Text(scrambled.resolved))\(Text(scrambled.glitch).foregroundStyle(Palette.pink))")
                .foregroundStyle(tag == .warn ? Palette.amber : Palette.phosphor)
                .lineLimit(1)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(entry.plainText)
    }

    private static func headerLabel(_ stage: RunStage) -> String {
        " STAGE \(stage.number) · \(stage.title.uppercased()) "
    }

    private func headerRow(stage: RunStage, age: TimeInterval) -> some View {
        let scrambled = ScrambleText.render(Self.headerLabel(stage), age: age, seed: stage.rawValue + 7)
        let fill = String(repeating: "═", count: max(0, 12 - stage.title.count))
        return HStack(spacing: 6) {
            timestamp
            Text("╔═\(scrambled.resolved)\(scrambled.glitch)═\(fill)╗")
                .foregroundStyle(stage.color)
                .shadow(color: style == .crt ? stage.color.opacity(0.8) : .clear, radius: 3)
                .lineLimit(1)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Stage \(stage.number), \(stage.title)")
        .accessibilityAddTraits(.isHeader)
    }

    @ViewBuilder
    private var timestamp: some View {
        if showTimestamp {
            Text(entry.timestamp)
                .foregroundStyle(Palette.phosphor.opacity(0.38))
        }
    }
}

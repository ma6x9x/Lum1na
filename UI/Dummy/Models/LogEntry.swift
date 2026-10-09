import Foundation

/// A single console entry. Reveal, glitch and spinner animations are derived
/// from `createdAt` by the views, so the model only appends and settles entries.
struct LogEntry: Identifiable, Equatable, Sendable {
    let id = UUID()
    let timestamp: String
    let createdAt: Date
    var kind: LogKind
    let text: String
    /// Set when the work the entry describes has finished (stops hex scrolling).
    var isSettled = false

    /// Plain-text rendering used by Copy.
    var plainText: String {
        switch kind {
        case .line(let tag):
            "\(tag.chipText) \(text)"
        case .art(let artwork):
            artwork.plainRows.joined(separator: "\n")
        case .header(let stage):
            "╔═ STAGE \(stage.number) · \(stage.title.uppercased()) ═╗"
        case .meter(let stage):
            "\(stage.title.uppercased()) ████████████ 100%"
        case .hexDump(let seed):
            HexDump.rows(seed: seed, offset: 40 + seed).joined(separator: "\n")
        }
    }
}

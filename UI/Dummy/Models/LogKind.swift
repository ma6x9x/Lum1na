import Foundation

/// What a console entry renders as. Every kind is purely decorative.
enum LogKind: Equatable, Sendable {
    /// A tagged text line (`[ OK ] …`); `.busy` lines show a braille spinner.
    case line(LogTag)
    /// Block-character pixel art revealed row by row.
    case art(PixelArtwork)
    /// Box-drawing stage header, e.g. `╔═ STAGE 2 · PATCHSET ═╗`.
    case header(RunStage)
    /// Dithered `░▒▓█` progress meter for a stage.
    case meter(RunStage)
    /// A short scrolling fake hex block while a stage works.
    case hexDump(seed: Int)
}

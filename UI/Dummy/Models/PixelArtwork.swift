import Foundation

/// Block-character artwork for the console. Cell codes: `█` letter body,
/// `1` accent (gradient) body, `▓` dithered shadow, `s` star body, `*` star core.
enum PixelArtwork: Equatable, Sendable {
    /// Pixel star beside a LUM1NA banner.
    case lumina
    /// ILLUMINATED success banner.
    case illuminated

    var rows: [String] {
        switch self {
        case .lumina: Self.luminaRows
        case .illuminated: Self.illuminatedRows
        }
    }

    /// Rows as plain block characters (for copy / VoiceOver-free export).
    var plainRows: [String] {
        rows.map { row in
            String(row.map { cell -> Character in
                switch cell {
                case "1", "s", "*": "█"
                case ".": " "
                default: cell
                }
            })
        }
    }

    static let star: [String] = [
        "......s......",
        "......s......",
        "......s......",
        ".....sss.....",
        "....sssss....",
        "...sss*sss...",
        ".ssss***ssss.",
        "...sss*sss...",
        "....sssss....",
        ".....sss.....",
        "......s......",
        "......s......",
        "......s......"
    ]

    private static let luminaRows: [String] = {
        let banner = PixelFont.banner("LUM1NA")
        let blank = String(repeating: " ", count: banner[0].count)
        return star.enumerated().map { index, starRow in
            let bannerRow = (3..<11).contains(index) ? banner[index - 3] : blank
            return starRow + "   " + bannerRow
        }
    }()

    private static let illuminatedRows: [String] = PixelFont.banner("ILLUMINATED")
}

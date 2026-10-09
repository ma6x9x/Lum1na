import Foundation

/// Visual treatment of the console. `crt` is the retro pixel terminal
/// (phosphor glow, scanlines, mask, flicker); `clean` is a plain monospaced log.
enum ConsoleStyle: String, CaseIterable, Identifiable, Sendable {
    case crt
    case clean

    var id: String { rawValue }

    var label: String {
        switch self {
        case .crt: "CRT"
        case .clean: "Clean"
        }
    }
}

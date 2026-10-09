import Foundation

/// The coloured pixel chip shown in front of a console line.
enum LogTag: Equatable, Sendable {
    case ok
    case busy
    case warn
    case info

    /// Fixed-width chip text, e.g. `[ OK ]`.
    var chipText: String {
        switch self {
        case .ok: "[ OK ]"
        case .busy: "[ .. ]"
        case .warn: "[WARN]"
        case .info: "[INFO]"
        }
    }
}

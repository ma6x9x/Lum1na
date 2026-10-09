import Foundation

/// Console verbosity. Verbose shows timestamps and every line; Compact hides
/// timestamps and condenses the stream.
enum ConsoleMode: String, CaseIterable, Identifiable, Sendable {
    case verbose
    case compact

    var id: String { rawValue }

    var label: String {
        switch self {
        case .verbose: "Verbose"
        case .compact: "Compact"
        }
    }

    var showsTimestamps: Bool { self == .verbose }
}

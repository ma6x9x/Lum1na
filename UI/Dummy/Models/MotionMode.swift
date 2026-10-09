import Foundation

/// User-selectable motion intensity in Settings.
enum MotionMode: String, CaseIterable, Identifiable, Sendable {
    case full
    case subtle
    case off

    var id: String { rawValue }

    var label: String {
        switch self {
        case .full: "Full"
        case .subtle: "Subtle"
        case .off: "Off"
        }
    }

    var level: MotionLevel {
        switch self {
        case .full: .full
        case .subtle: .subtle
        case .off: .off
        }
    }
}

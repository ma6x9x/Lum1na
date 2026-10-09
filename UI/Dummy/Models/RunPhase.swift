import Foundation

/// High-level state of the simulated (non-functional) run.
enum RunPhase: Equatable, Sendable {
    case idle
    case running
    case success
    case cancelled
}

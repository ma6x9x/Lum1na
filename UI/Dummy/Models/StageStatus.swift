import Foundation

/// Visual status of a single stage row.
enum StageStatus: Equatable, Sendable {
    case pending
    case active
    case done
}

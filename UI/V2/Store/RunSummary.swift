//
//  RunSummary.swift
//  Lum1na — pinned chip after a test finishes.
//

import Foundation

struct RunSummary: Identifiable, Equatable {
    let id: UUID
    let catalogId: String
    let displayName: String
    let status: Status
    let keyValues: [String]
    let duration: TimeInterval
    let finishedAt: Date
    let lineSnapshot: [ConsoleLine]

    enum Status: String, Equatable {
        case ok
        case failed
        case gated
        case cancelled

        var symbol: String {
            switch self {
            case .ok: return "checkmark.circle.fill"
            case .failed: return "xmark.circle.fill"
            case .gated: return "lock.fill"
            case .cancelled: return "pause.circle.fill"
            }
        }
    }

    init(
        id: UUID = UUID(),
        catalogId: String,
        displayName: String,
        status: Status,
        keyValues: [String],
        duration: TimeInterval,
        finishedAt: Date = Date(),
        lineSnapshot: [ConsoleLine]
    ) {
        self.id = id
        self.catalogId = catalogId
        self.displayName = displayName
        self.status = status
        self.keyValues = keyValues
        self.duration = duration
        self.finishedAt = finishedAt
        self.lineSnapshot = lineSnapshot
    }
}

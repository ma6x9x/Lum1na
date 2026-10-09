import Foundation

/// The four cosmetic stages shown during a simulated run.
///
/// None of these perform real work — the names are purely thematic.
enum RunStage: Int, CaseIterable, Identifiable, Sendable {
    case kernel
    case patchset
    case sandbox
    case daemon

    var id: Int { rawValue }

    /// 1-based display number.
    var number: Int { rawValue + 1 }

    var title: String {
        switch self {
        case .kernel: "Kernel"
        case .patchset: "Patchset"
        case .sandbox: "Sandbox"
        case .daemon: "Daemon"
        }
    }

    /// SF Symbol for the stage node on the board.
    var symbol: String {
        switch self {
        case .kernel: "cpu"
        case .patchset: "bandage"
        case .sandbox: "lock.shield"
        case .daemon: "gearshape.2"
        }
    }

    /// Board corner of the node: Kernel top-leading, then clockwise.
    var corner: (x: Double, y: Double) {
        switch self {
        case .kernel: (-1, -1)
        case .patchset: (1, -1)
        case .sandbox: (1, 1)
        case .daemon: (-1, 1)
        }
    }

    /// Generic, theatrical working line (no real techniques).
    var workingLine: String {
        switch self {
        case .kernel: "Aligning kernel lattice…"
        case .patchset: "Weaving patch threads…"
        case .sandbox: "Calibrating sandbox field…"
        case .daemon: "Synchronizing daemon pulse…"
        }
    }

    var completeLine: String {
        "\(title) stage complete"
    }

    static func from(_ stage: ExploitStage) -> RunStage {
        switch stage {
        case .kernel: .kernel
        case .patchset: .patchset
        case .sandbox: .sandbox
        case .daemon: .daemon
        }
    }
}

import Foundation

/// The run state the circuit board needs to light itself, decoupled from the
/// model so board views only re-render when one of these values changes.
struct BoardSnapshot: Equatable, Sendable {
    var phase: RunPhase = .idle
    var activeStage: Int = -1
    var completedStages: Int = 0
    var progress: Double = 0
    var successDate: Date?
    /// When true, `litMask` bits (1 << stage raw value) decide which buses stay lit.
    var usesMask: Bool = false
    var litMask: Int = 0

    /// 0…1 overall energy: raises pulse speed and trace glow.
    var energy: Double {
        switch phase {
        case .success: 1
        case .running: 0.25 + 0.75 * progress
        default: 0.12
        }
    }

    /// Star brightness, stepping up per completed stage.
    var starIntensity: Double {
        phase == .success ? 1 : 0.42 + 0.14 * Double(completedStages)
    }

    func isLit(_ stage: Int) -> Bool {
        if phase == .success { return true }
        if usesMask { return (litMask & (1 << stage)) != 0 }
        return stage < completedStages
    }
    func isActive(_ stage: Int) -> Bool { phase == .running && stage == activeStage }
}

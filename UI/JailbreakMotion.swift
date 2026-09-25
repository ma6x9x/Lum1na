import SwiftUI

/// Single motion driver for the home board. Views must not invent their
/// own “are we running” logic. Success only follows `lastResult.isSuccess`.
enum BoardMotion: Equatable {
    case idle
    case arming(ExploitStage)
    case firing(ExploitStage, progress: Double)
    case chaining(progress: Double, stage: ExploitStage?)
    case success
    case failed
    case recovered

    @MainActor
    static func from(_ manager: ExploitManager, recovered: Bool) -> BoardMotion {
        if manager.isRunning {
            if manager.fullChainActive {
                return .chaining(progress: manager.progress, stage: manager.selectedStage)
            }
            if let stage = manager.selectedStage {
                return .firing(stage, progress: manager.progress)
            }
            return .chaining(progress: manager.progress, stage: nil)
        }
        if manager.lastResult.isSuccess { return .success }
        if recovered { return .recovered }
        if case .failure = manager.lastResult { return .failed }
        if let stage = manager.selectedStage { return .arming(stage) }
        return .idle
    }

    var liveRails: Set<ExploitStage> {
        switch self {
        case .chaining(let p, let stage):
            var set: Set<ExploitStage> = []
            if p >= 0.08 { set.insert(.kernel) }
            if p >= 0.30 { set.insert(.patchset) }
            if p >= 0.50 { set.insert(.sandbox) }
            if p >= 0.72 { set.insert(.daemon) }
            if p >= 0.90 { set = Set(ExploitStage.allCases) }
            if let stage { set.insert(stage) }
            return set
        case .firing(let stage, _):
            return [stage]
        case .success:
            return Set(ExploitStage.allCases)
        default:
            return []
        }
    }

    var starAmp: CGFloat {
        switch self {
        case .firing, .chaining: return 0.08
        case .success: return 0.05
        case .failed, .recovered: return 0.012
        default: return 0.03
        }
    }

    var starBloom: CGFloat {
        switch self {
        case .chaining: return 22
        case .firing: return 18
        case .success: return 28
        case .failed, .recovered: return 6
        default: return 12
        }
    }

    var galaxySpeed: Double {
        switch self {
        case .firing, .chaining: return 1.4
        default: return 1.0
        }
    }
}

struct LuminaPressStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .animation(.spring(response: 0.28, dampingFraction: 0.72), value: configuration.isPressed)
    }
}

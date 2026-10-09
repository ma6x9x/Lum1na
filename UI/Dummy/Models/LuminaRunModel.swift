import SwiftUI
import Observation

/// Drives the simulated run. **Nothing here does any real work**: every stage,
/// log line and progress value is produced by `Task.sleep` timers only. The
/// timeline mirrors `preview/index.html` (~10 s for the four stages).
@MainActor
@Observable
final class LuminaRunModel {
    private(set) var phase: RunPhase = .idle
    private(set) var currentStageIndex: Int = -1
    private(set) var completedStages: Int = 0
    private(set) var progress: Double = 0
    private(set) var logs: [LogEntry] = []
    /// When the run reached success; drives the board surge and confetti.
    private(set) var successDate: Date?

    /// Incremented each time a stage finishes — a stable trigger for haptics.
    private(set) var stageTickCount: Int = 0

    private var runTask: Task<Void, Never>?
    private var liveLinked = false
    private var litMask = 0

    var isRunning: Bool { phase == .running }
    var isFinished: Bool { phase == .success }

    /// Status for a given stage, derived from counters.
    func status(for stage: RunStage) -> StageStatus {
        if liveLinked {
            if phase == .success { return .done }
            if (litMask & (1 << stage.rawValue)) != 0 { return .done }
            if stage.rawValue == currentStageIndex && phase == .running { return .active }
            return .pending
        }
        if stage.rawValue < completedStages { return .done }
        if stage.rawValue == currentStageIndex && phase == .running { return .active }
        return .pending
    }

    var statusText: String {
        switch phase {
        case .idle: "Ready"
        case .running: "Running"
        case .success: "Illuminated"
        case .cancelled: "Cancelled"
        }
    }

    /// "STEP n OF 4" progress label.
    var stepText: String {
        let step = min(max(completedStages + (isRunning ? 1 : 0), 1), RunStage.allCases.count)
        return "STEP \(step) OF \(RunStage.allCases.count)"
    }

    var boardSnapshot: BoardSnapshot {
        BoardSnapshot(
            phase: phase,
            activeStage: currentStageIndex,
            completedStages: completedStages,
            progress: progress,
            successDate: successDate,
            usesMask: liveLinked,
            litMask: litMask
        )
    }

    /// Mirrors the live chain onto the board. Success only when kread is proven.
    func applyLive(running: Bool, stage: ExploitStage?, progress liveProgress: Double, proven: Bool) {
        liveLinked = true
        runTask?.cancel()
        runTask = nil
        if proven && !running {
            if phase != .success { successDate = .now }
            phase = .success
            progress = 1
            currentStageIndex = -1
            litMask = 0b1111
            completedStages = RunStage.allCases.count
            return
        }
        guard running else {
            phase = .idle
            currentStageIndex = -1
            litMask = 0
            completedStages = 0
            progress = 0
            successDate = nil
            return
        }
        phase = .running
        successDate = nil
        progress = liveProgress
        if let stage {
            let mapped = RunStage.from(stage).rawValue
            if currentStageIndex >= 0 && currentStageIndex != mapped {
                litMask |= 1 << currentStageIndex
            }
            currentStageIndex = mapped
        }
        completedStages = (0..<RunStage.allCases.count).reduce(0) { $0 + ((litMask >> $1) & 1) }
    }

    // MARK: - Control

    func illuminate() {
        guard phase != .running else { return }
        resetState()
        phase = .running
        runTask = Task { [self] in
            await performRun()
        }
    }

    func cancel() {
        guard phase == .running else { return }
        runTask?.cancel()
        runTask = nil
        phase = .cancelled
        currentStageIndex = -1
        append(.line(.warn), "Run cancelled.")
    }

    func reset() {
        runTask?.cancel()
        runTask = nil
        resetState()
        phase = .idle
    }

    private func resetState() {
        logs.removeAll()
        currentStageIndex = -1
        completedStages = 0
        progress = 0
        stageTickCount = 0
        successDate = nil
    }

    // MARK: - Simulation (timers only)

    private func performRun() async {
        append(.art(.lumina))
        guard await pause(560) else { return }
        let boot = append(.line(.busy), "Waking the constellation core")
        guard await pause(300) else { return }
        retag(boot, .ok)
        guard await pause(90) else { return }

        for stage in RunStage.allCases {
            guard await runStage(stage) else { return }
        }

        if Task.isCancelled { return }
        progress = 1
        currentStageIndex = -1
        successDate = .now
        phase = .success
        append(.art(.illuminated))
        guard await pause(520) else { return }
        append(.line(.ok), "All lights aligned. Enjoy the glow.")
    }

    /// One ~2.3 s stage: header, spinner line, hex block, meter, ramp, settle.
    private func runStage(_ stage: RunStage) async -> Bool {
        currentStageIndex = stage.rawValue
        append(.header(stage))
        guard await pause(150) else { return false }
        let busy = append(.line(.busy), stage.workingLine)
        guard await pause(150) else { return false }
        let hex = append(.hexDump(seed: stage.rawValue * 7 + 3))
        guard await pause(50) else { return false }
        append(.meter(stage))

        let start = progress
        let target = Double(stage.number) / Double(RunStage.allCases.count)
        let steps = 32
        for step in 1...steps {
            guard await pause(50) else { return false }
            progress = start + (target - start) * Double(step) / Double(steps)
            if stage == .sandbox && step == 14 {
                append(.line(.warn), "Field drift detected · re-tuning")
            }
        }

        completedStages = stage.number
        stageTickCount += 1
        retag(busy, .ok)
        settle(hex)
        guard await pause(40) else { return false }
        append(.line(.ok), stage.completeLine)
        return await pause(310)
    }

    // MARK: - Helpers

    @discardableResult
    private func append(_ kind: LogKind, _ text: String = "") -> UUID {
        let entry = LogEntry(timestamp: Self.timestamp(), createdAt: .now, kind: kind, text: text)
        logs.append(entry)
        return entry.id
    }

    private func retag(_ id: UUID, _ tag: LogTag) {
        guard let index = logs.firstIndex(where: { $0.id == id }) else { return }
        logs[index].kind = .line(tag)
    }

    private func settle(_ id: UUID) {
        guard let index = logs.firstIndex(where: { $0.id == id }) else { return }
        logs[index].isSettled = true
    }

    /// Returns `false` if the run was cancelled during the wait.
    private func pause(_ ms: Int) async -> Bool {
        do {
            try await Task.sleep(for: .milliseconds(ms))
            return !Task.isCancelled
        } catch {
            return false
        }
    }

    /// Plain-text dump for the copy button.
    var plainTextLog: String {
        logs.map { entry in
            if case .art = entry.kind { return entry.plainText }
            return "[\(entry.timestamp)] \(entry.plainText)"
        }
        .joined(separator: "\n")
    }

    static func timestamp() -> String {
        let c = Calendar.current.dateComponents([.hour, .minute, .second], from: .now)
        return String(format: "%02d:%02d:%02d", c.hour ?? 0, c.minute ?? 0, c.second ?? 0)
    }
}

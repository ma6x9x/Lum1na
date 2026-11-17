//
//  LuminaAppStore.swift
//  Lum1na — @Observable façade over ExploitManager (views never call ObjC Exploit classes).
//

import Combine
import Foundation
import Observation
import SwiftUI
import UIKit

@MainActor
@Observable
final class LuminaAppStore {
    // MARK: Mirrored ExploitManager state
    var lines: [ConsoleLine] = []
    var isRunning: Bool = false
    var progress: Double = 0
    var lastResult: ExploitResult = .idle
    var currentKernelSlide: UInt64 = 0
    var currentKernelBase: UInt64 = 0
    var fullChainActive: Bool = false
    var selectedStage: ExploitStage?
    var lastRecoverySummary: String = ""
    var lastRecoveryTranscript: String = ""

    // MARK: Device / honesty
    var machine: String = DeviceUtils.currentDeviceIdentifier
    var boardConfig: String = ""
    var iosVersion: String = DeviceUtils.marketingVersion
    var build: String = DeviceUtils.osversion
    var skuTag: String = labOffsetTag()
    var hasKread: Bool = false
    var conversionConfirmed: Bool = false
    var magicConfirmed: Bool = false
    var lastTapId: String? = nil

    // MARK: UI session
    var searchText: String = ""
    var expandedGroups: Set<TestGroup> = []
    var activeRunId: String?
    var activeRunName: String?
    var showResultsSheet: Bool = false
    /// When set, results overlay shows this snapshot instead of the live buffer.
    var viewingSummary: RunSummary? = nil
    var pinnedSummary: RunSummary?
    var expandPinned: Bool = false
    var showSettings: Bool = false
    var showTerminal: Bool = false
    var showHourLogs: Bool = false
    var consolePaused: Bool = false
    var consoleQuery: String = ""
    var consoleLevelFilter: ConsoleLevelFilter = .all
    var selectedTab: LuminaTab = .tests
    var runStartedAt: Date?
    var toastMessage: String?
    var showRunConfirm: Bool = false
    var pendingConfirmEntry: ExploitCatalogEntry?
    var shareText: String?
    var showShareSheet: Bool = false

    var settings = LuminaV2Settings()

    @ObservationIgnored private let manager = ExploitManager.shared
    @ObservationIgnored private var bag = Set<AnyCancellable>()
    @ObservationIgnored private var honestyTimer: Timer?
    @ObservationIgnored private var collapseWorkItem: DispatchWorkItem?

    enum LuminaTab: Hashable {
        case tests, chains, console, tools
    }

    enum ConsoleLevelFilter: String, CaseIterable, Identifiable {
        case all = "All levels"
        case lum1na = "lum1na"
        case kernel = "kernel"
        case subsystem = "subsystem"
        case error = "Error+"
        var id: String { rawValue }
    }

    init() {
        expandedGroups = [settings.defaultGroup, .taps]
        boardConfig = LuminaAppStore.readBoardConfig()
        bind()
        refreshHonesty()
        honestyTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshHonesty() }
        }
        // Apply default console level preference as initial chip when Error-focused.
        if settings.defaultLogLevel == .error {
            consoleLevelFilter = .error
        }
    }

    deinit {
        honestyTimer?.invalidate()
        honestyTimer = nil
        collapseWorkItem?.cancel()
    }

    private func bind() {
        manager.$lines
            .receive(on: RunLoop.main)
            .sink { [weak self] value in
                guard let self, !self.consolePaused || self.isRunning else { return }
                if !self.consolePaused {
                    let limit = max(self.settings.bufferSize, 500)
                    self.lines = value.count > limit ? Array(value.suffix(limit)) : value
                }
            }
            .store(in: &bag)
        manager.$isRunning
            .receive(on: RunLoop.main)
            .sink { [weak self] running in
                guard let self else { return }
                let was = self.isRunning
                self.isRunning = running
                if was && !running {
                    self.finishActiveRun()
                }
            }
            .store(in: &bag)
        manager.$progress.receive(on: RunLoop.main).sink { [weak self] in self?.progress = $0 }.store(in: &bag)
        manager.$lastResult.receive(on: RunLoop.main).sink { [weak self] in self?.lastResult = $0 }.store(in: &bag)
        manager.$currentKernelSlide.receive(on: RunLoop.main).sink { [weak self] in self?.currentKernelSlide = $0 }.store(in: &bag)
        manager.$currentKernelBase.receive(on: RunLoop.main).sink { [weak self] in self?.currentKernelBase = $0 }.store(in: &bag)
        manager.$fullChainActive.receive(on: RunLoop.main).sink { [weak self] in self?.fullChainActive = $0 }.store(in: &bag)
        manager.$selectedStage.receive(on: RunLoop.main).sink { [weak self] in self?.selectedStage = $0 }.store(in: &bag)
        manager.$lastRecoverySummary.receive(on: RunLoop.main).sink { [weak self] in self?.lastRecoverySummary = $0 }.store(in: &bag)
        manager.$lastRecoveryTranscript.receive(on: RunLoop.main).sink { [weak self] in self?.lastRecoveryTranscript = $0 }.store(in: &bag)

        lines = manager.lines
        isRunning = manager.isRunning
        progress = manager.progress
        lastResult = manager.lastResult
        currentKernelSlide = manager.currentKernelSlide
        currentKernelBase = manager.currentKernelBase
        fullChainActive = manager.fullChainActive
        selectedStage = manager.selectedStage
        lastRecoverySummary = manager.lastRecoverySummary
        lastRecoveryTranscript = manager.lastRecoveryTranscript
    }

    func refreshHonesty() {
        hasKread = Lum1naBoard.shared().hasKread
        conversionConfirmed = LabLearn.conversionConfirmed()
        magicConfirmed = LabLearn.magicConfirmed()
        lastTapId = PersistentLogStore.shared.lastTapId()
        machine = DeviceUtils.currentDeviceIdentifier
        iosVersion = DeviceUtils.marketingVersion
        build = DeviceUtils.osversion
        skuTag = labOffsetTag()
        boardConfig = Self.readBoardConfig()
    }

    static func readBoardConfig() -> String {
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        guard size > 0 else { return "?" }
        var buf = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &buf, &size, nil, 0)
        let s = String(cString: buf)
        return s.isEmpty ? "?" : s
    }

    // MARK: Catalog

    var catalogEntries: [ExploitCatalogEntry] {
        CatalogMetadata.visibleCatalog()
    }

    func badges(for entry: ExploitCatalogEntry) -> [(HonestyBadgeKind, Bool)] {
        let meta = CatalogMetadata.meta(for: entry)
        let kinds = meta.staticBadges.isEmpty
            ? [HonestyBadgeKind.reach, .window, .conversion]
            : Array(meta.staticBadges.prefix(4))
        return kinds.map { kind in (kind, isBadgeMet(kind, entry: entry, meta: meta)) }
    }

    private func isBadgeMet(_ kind: HonestyBadgeKind, entry: ExploitCatalogEntry, meta: CatalogUIMeta) -> Bool {
        switch kind {
        case .reach:
            // Catalog entry is wired into the visible catalog.
            return true
        case .window:
            // Met when last result for this id mentions window=open / window hit, or timing probe last ok.
            if let pinned = pinnedSummary, pinned.catalogId == entry.id {
                let blob = pinned.lineSnapshot.map(\.message).joined(separator: "\n").lowercased()
                if blob.contains("window=open") || blob.contains("window open") { return true }
                if pinned.status == .ok && (entry.id.contains("timing") || blob.contains("window")) { return true }
            }
            return false
        case .conversion:
            return conversionConfirmed
        case .hasKread:
            return hasKread || magicConfirmed
        case .after:
            // Met only after a real hasKread/magic honesty flip (never session-global guess alone).
            guard hasKread || magicConfirmed else { return false }
            return entry.id == "afterkread"
                || entry.id.hasPrefix("krw")
                || meta.staticBadges.contains(.after)
                || (pinnedSummary?.catalogId == entry.id && pinnedSummary?.status == .ok)
        case .armGated:
            // Gate badge is informational when present; "met" means currently locked/gated.
            if hasKread { return false }
            return true
        case .closed:
            return true
        }
    }

    func groupedCatalog(matching query: String) -> [(TestGroup, [ExploitCatalogEntry])] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var buckets: [TestGroup: [ExploitCatalogEntry]] = Dictionary(uniqueKeysWithValues: TestGroup.allCases.map { ($0, []) })
        for entry in catalogEntries {
            let meta = CatalogMetadata.meta(for: entry)
            if !q.isEmpty {
                let hay = (meta.displayName + " " + entry.id + " " + entry.description).lowercased()
                if !hay.contains(q) { continue }
            }
            buckets[meta.group, default: []].append(entry)
        }
        let order: [TestGroup] = [.probes, .taps, .chains, .kernelReads, .parked]
        return order.compactMap { g in
            let items = buckets[g] ?? []
            return items.isEmpty ? nil : (g, items)
        }
    }

    // MARK: Run

    func requestRun(_ entry: ExploitCatalogEntry) {
        if settings.confirmBeforeRun && !isRunning {
            pendingConfirmEntry = entry
            showRunConfirm = true
            return
        }
        startRun(entry)
    }

    func confirmPendingRun() {
        guard let entry = pendingConfirmEntry else { return }
        pendingConfirmEntry = nil
        showRunConfirm = false
        startRun(entry)
    }

    func cancelPendingRun() {
        pendingConfirmEntry = nil
        showRunConfirm = false
    }

    func startRun(_ entry: ExploitCatalogEntry) {
        guard !isRunning else {
            toastMessage = "Already running"
            return
        }
        collapseWorkItem?.cancel()
        activeRunId = entry.id
        activeRunName = CatalogMetadata.meta(for: entry).displayName
        runStartedAt = Date()
        viewingSummary = nil
        showResultsSheet = true
        expandPinned = false
        Task { await manager.executeExploit(entry) }
    }

    func runStage(_ stage: String, displayName: String) {
        guard !isRunning else {
            toastMessage = "Already running"
            return
        }
        collapseWorkItem?.cancel()
        activeRunId = stage
        activeRunName = displayName
        runStartedAt = Date()
        viewingSummary = nil
        showResultsSheet = true
        Task { await manager.executeStage(stage) }
    }

    func runFullChain() {
        runStage("FULL CHAIN", displayName: "Full Chain")
    }

    func runCatalogId(_ id: String) {
        guard let entry = catalogEntries.first(where: { $0.id == id }) else {
            toastMessage = "Unknown catalog id \(id)"
            return
        }
        if settings.confirmBeforeRun && !isRunning {
            pendingConfirmEntry = entry
            showRunConfirm = true
            return
        }
        startRun(entry)
    }

    func reopenPinnedSummary() {
        guard let summary = pinnedSummary else { return }
        viewingSummary = summary
        activeRunId = summary.catalogId
        activeRunName = summary.displayName
        showResultsSheet = true
    }

    func dismissResultsToChip() {
        showResultsSheet = false
        viewingSummary = nil
    }

    private func finishActiveRun() {
        guard let id = activeRunId else { return }
        let name = activeRunName ?? id
        let duration = Date().timeIntervalSince(runStartedAt ?? Date())
        let snap = Array(lines.suffix(max(80, min(settings.bufferSize, 400))))
        let status = deriveStatus(from: snap, result: lastResult)
        let keys = deriveKeyValues(from: snap)
        let summary = RunSummary(
            catalogId: id,
            displayName: name,
            status: status,
            keyValues: keys,
            duration: duration,
            lineSnapshot: snap
        )
        if settings.pinLastSummary {
            pinnedSummary = summary
            viewingSummary = summary
        }
        refreshHonesty()

        // Short settle, then collapse sheet → pinned chip (visible on every tab).
        collapseWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            withAnimation(LuminaV2Theme.spring) {
                self.showResultsSheet = false
            }
        }
        collapseWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.85, execute: work)
    }

    private func deriveStatus(from lines: [ConsoleLine], result: ExploitResult) -> RunSummary.Status {
        if case .failure = result { return .failed }
        if case .success = result { return .ok }
        let text = lines.map(\.message).joined(separator: "\n").lowercased()
        if text.contains("arm-gated") || text.contains("hold until") || text.contains("refuses") {
            return .gated
        }
        if text.contains("[-]") || text.contains("failed") || text.contains("panic") {
            return .failed
        }
        if text.contains("[+]") || text.contains(" ok") || text.contains("completed") {
            return .ok
        }
        return .ok
    }

    private func deriveKeyValues(from lines: [ConsoleLine]) -> [String] {
        var keys: [String] = []
        let blob = lines.map(\.message).joined(separator: "\n")
        if hasKread { keys.append("hasKread=yes") }
        if conversionConfirmed { keys.append("conv=yes") }
        else if blob.lowercased().contains("conv=") {
            if let r = blob.range(of: #"conv=\w+"#, options: .regularExpression) {
                keys.append(String(blob[r]))
            }
        }
        if blob.lowercased().contains("window=") {
            if let r = blob.range(of: #"window=\w+"#, options: .regularExpression) {
                keys.append(String(blob[r]))
            }
        }
        if blob.lowercased().contains("reach=") {
            if let r = blob.range(of: #"reach=\w+"#, options: .regularExpression) {
                keys.append(String(blob[r]))
            }
        }
        if keys.isEmpty {
            keys.append(hasKread ? "board ready" : "board idle")
        }
        return Array(keys.prefix(3))
    }

    // MARK: Chain rung receipts

    enum RungUIState: Equatable {
        case pending
        case running
        case ok
        case failed
        case gated

        var label: String {
            switch self {
            case .pending: return "pending"
            case .running: return "running…"
            case .ok: return "ok"
            case .failed: return "failed"
            case .gated: return "ARM-GATED"
            }
        }

        var color: Color {
            switch self {
            case .pending: return LuminaV2Theme.pending
            case .running: return LuminaV2Theme.accent
            case .ok: return LuminaV2Theme.ok
            case .failed: return LuminaV2Theme.danger
            case .gated: return LuminaV2Theme.amber
            }
        }

        var symbol: String {
            switch self {
            case .pending: return "circle"
            case .running: return "circle.fill"
            case .ok: return "checkmark.circle.fill"
            case .failed: return "xmark.circle.fill"
            case .gated: return "lock.fill"
            }
        }
    }

    func rungStates(for steps: [String], chainId: String, active: Bool) -> [RungUIState] {
        let blob = lines.map(\.message).joined(separator: "\n")
        let lower = blob.lowercased()
        var states = Array(repeating: RungUIState.pending, count: steps.count)

        func stepHit(_ step: String) -> Bool {
            let s = step.lowercased()
            if lower.contains("stage: \(s)") { return true }
            if lower.contains("[chain] \(s)") { return true }
            if lower.contains("step ") && lower.contains(s) { return true }
            if lower.contains(s) && (lower.contains(" ok") || lower.contains("[+]") || lower.contains("done")) {
                return true
            }
            return lower.contains(s)
        }

        func stepGated(_ step: String) -> Bool {
            let s = step.lowercased()
            return lower.contains(s) && (
                lower.contains("arm-gated") || lower.contains("hold") || lower.contains("refuses")
            )
        }

        func stepFailed(_ step: String) -> Bool {
            let s = step.lowercased()
            return lower.contains(s) && (lower.contains("[-]") || lower.contains("failed") || lower.contains("panic"))
        }

        // Progress-based fallback for FULL CHAIN / KERNEL sequencers.
        let progressIndex: Int? = {
            guard active, steps.count > 1 else { return nil }
            let p = progress
            if p <= 0 { return 0 }
            let idx = min(steps.count - 1, max(0, Int(p * Double(steps.count))))
            return idx
        }()

        var lastTouched = -1
        for (i, step) in steps.enumerated() {
            if stepGated(step) {
                states[i] = .gated
                lastTouched = i
            } else if stepFailed(step) {
                states[i] = .failed
                lastTouched = i
                if settings.stopOnFailure {
                    // leave rest pending
                    break
                }
            } else if stepHit(step) {
                states[i] = .ok
                lastTouched = i
            }
        }

        if active {
            let runningIdx = progressIndex ?? max(lastTouched, 0)
            if runningIdx < states.count {
                if states[runningIdx] == .pending || states[runningIdx] == .ok {
                    states[runningIdx] = .running
                }
                for j in 0..<runningIdx {
                    if states[j] == .pending { states[j] = .ok }
                }
            }
        } else if let pinned = pinnedSummary, matchesChain(pinned, chainId: chainId) {
            switch pinned.status {
            case .ok:
                states = states.map { $0 == .pending ? .ok : $0 }
                // If nothing was parsed, paint all ok.
                if states.allSatisfy({ $0 == .pending || $0 == .ok }) {
                    states = Array(repeating: .ok, count: steps.count)
                }
            case .gated:
                if let idx = states.lastIndex(where: { $0 != .pending }) {
                    states[idx] = .gated
                } else if !states.isEmpty {
                    let mid = min(steps.count - 1, max(0, steps.count / 2))
                    for j in 0..<mid { states[j] = .ok }
                    states[mid] = .gated
                }
            case .failed:
                if let idx = states.lastIndex(where: { $0 != .pending }) {
                    states[idx] = .failed
                } else if !states.isEmpty {
                    states[0] = .failed
                }
            case .cancelled:
                break
            }
        }

        return states
    }

    func rungProgressLabel(states: [RungUIState]) -> String {
        let done = states.filter { $0 == .ok || $0 == .gated || $0 == .failed }.count
        return "\(done) of \(states.count)"
    }

    private func matchesChain(_ pinned: RunSummary, chainId: String) -> Bool {
        if pinned.catalogId == chainId { return true }
        if chainId == "full", pinned.catalogId == "FULL CHAIN" || pinned.displayName.lowercased().contains("full chain") {
            return true
        }
        if chainId == "kernel", pinned.catalogId == "KERNEL" || pinned.displayName.lowercased().contains("kernel") {
            return true
        }
        return pinned.catalogId == chainId
    }

    // MARK: Console helpers

    func syncLinesFromManager() {
        let limit = max(settings.bufferSize, 500)
        let value = manager.lines
        lines = value.count > limit ? Array(value.suffix(limit)) : value
    }

    func peekUITree() {
        manager.log("=== peek session (in-app SwiftPeek twin) ===")
        PeekInspector.dump { self.manager.log($0) }
        manager.log("=== peek done ===")
        selectedTab = .console
        toastMessage = "Peek dumped to console"
    }

    func clearConsole() {
        manager.clearConsole()
        lines = manager.lines
    }

    func exportConsole() -> String {
        manager.exportFullDebugLog()
    }

    func resultsCopyText() -> String {
        if let snap = viewingSummary ?? (showResultsSheet && !isRunning ? pinnedSummary : nil) {
            return snap.snapshotText
        }
        if isRunning, let id = activeRunId {
            // Live run — prefer lines since run start; fall back to recent buffer.
            return lines.map(\.formatted).joined(separator: "\n")
                + "\n/* activeRun=\(id) */\n"
        }
        return viewingSummary?.snapshotText ?? ""
    }

    func share(_ text: String) {
        shareText = text
        showShareSheet = true
    }

    func resetSession() {
        manager.reset()
        pinnedSummary = nil
        viewingSummary = nil
        activeRunId = nil
        showResultsSheet = false
        refreshHonesty()
    }

    func copyToPasteboard(_ string: String) {
        UIPasteboard.general.string = string
        toastMessage = "Copied"
    }

    func knobValue(_ id: String) -> String {
        var buf: [CChar] = Array(repeating: 0, count: 256)
        return LabKnobRead(id, &buf, 256) == 1 ? String(cString: buf) : ""
    }

    func writeKnob(id: String, value: String) {
        LabKnobWrite(id, value)
    }

    var readyLabel: String {
        if isRunning { return "Running" }
        if hasKread { return "hasKread" }
        return "Ready"
    }

    var readyColor: Color {
        if isRunning { return LuminaV2Theme.accent }
        if hasKread { return LuminaV2Theme.ok }
        return LuminaV2Theme.ok
    }

    var appPid: Int32 { ProcessInfo.processInfo.processIdentifier }
}

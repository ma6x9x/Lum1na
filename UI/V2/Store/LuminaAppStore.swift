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
    var boardConfig: String = Self.readBoardConfig()
    var iosVersion: String = DeviceUtils.marketingVersion
    var build: String = DeviceUtils.osversion
    var skuTag: String = labOffsetTag()
    var hasKread: Bool = false
    var conversionConfirmed: Bool = false
    var magicConfirmed: Bool = false
    var lastTapId: String? = nil

    // MARK: UI session
    var searchText: String = ""
    var expandedGroups: Set<TestGroup> = [.probes, .taps]
    var activeRunId: String?
    var activeRunName: String?
    var showResultsSheet: Bool = false
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

    let settings = LuminaV2Settings()

    @ObservationIgnored private let manager = ExploitManager.shared
    @ObservationIgnored private var bag = Set<AnyCancellable>()
    @ObservationIgnored private var honestyTimer: Timer?

    enum LuminaTab: Hashable {
        case tests, chains, console, tools
    }

    enum ConsoleLevelFilter: String, CaseIterable, Identifiable {
        case all = "All levels"
        case info = "info"
        case warn = "warn"
        case error = "Error+"
        var id: String { rawValue }
    }

    init() {
        bind()
        refreshHonesty()
        honestyTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshHonesty() }
        }
    }

    private func bind() {
        manager.$lines
            .receive(on: RunLoop.main)
            .sink { [weak self] value in
                guard let self, !self.consolePaused || self.isRunning else { return }
                if !self.consolePaused {
                    self.lines = value
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

        // Seed
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

    private static func readBoardConfig() -> String {
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
        var out: [(HonestyBadgeKind, Bool)] = [
            (.reach, true), // catalog entry is wired = reachable in UI sense
            (.window, meta.staticBadges.contains(.window) || entry.description.lowercased().contains("window")),
            (.conversion, conversionConfirmed),
            (.hasKread, hasKread),
            (.after, hasKread && (entry.id == "afterkread" || entry.id == "krw")),
        ]
        if meta.staticBadges.contains(.armGated) || entry.description.lowercased().contains("hold until") {
            out.append((.armGated, true))
        }
        if meta.staticBadges.contains(.closed) {
            out.append((.closed, true))
        }
        return out
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
            // Present results sheet immediately; confirmation is lightweight (sheet = commit).
        }
        startRun(entry)
    }

    func startRun(_ entry: ExploitCatalogEntry) {
        guard !isRunning else {
            toastMessage = "Already running"
            return
        }
        activeRunId = entry.id
        activeRunName = CatalogMetadata.meta(for: entry).displayName
        runStartedAt = Date()
        showResultsSheet = true
        expandPinned = false
        Task { await manager.executeExploit(entry) }
    }

    func runStage(_ stage: String, displayName: String) {
        guard !isRunning else {
            toastMessage = "Already running"
            return
        }
        activeRunId = stage
        activeRunName = displayName
        runStartedAt = Date()
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
        startRun(entry)
    }

    private func finishActiveRun() {
        guard let id = activeRunId else { return }
        let name = activeRunName ?? id
        let duration = Date().timeIntervalSince(runStartedAt ?? Date())
        let snap = Array(lines.suffix(80))
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
        }
        // Keep sheet open briefly; user can dismiss. Collapse to chip when sheet dismissed.
        refreshHonesty()
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

    func syncLinesFromManager() {
        lines = manager.lines
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

    func resetSession() {
        manager.reset()
        pinnedSummary = nil
        activeRunId = nil
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
}

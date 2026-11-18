//
//  ChainsTabView.swift
//  Lum1na — live STEP/[chain] rung receipts + hold-to-reorder steps.
//

import SwiftUI
import UniformTypeIdentifiers

struct ChainDefinition: Identifiable, Equatable {
    let id: String
    let title: String
    let subtitle: String
    var steps: [String]
    let run: RunKind

    enum RunKind: Equatable {
        case stage(String)
        case catalog(String)
        case fullChain
    }
}

enum LuminaChainCatalog {
    static let seed: [ChainDefinition] = [
        ChainDefinition(
            id: "full",
            title: "Full Chain",
            subtitle: "SANDBOX → KERNEL T1 → DAEMON → PATCHSET",
            steps: ["SANDBOX", "KERNEL", "DAEMON", "PATCHSET"],
            run: .fullChain
        ),
        ChainDefinition(
            id: "kernel",
            title: "KERNEL stage",
            subtitle: "T1 SKU door sequencer (executeStage KERNEL)",
            steps: ["Ident / board", "T1 SKU door", "kread gate", "AfterKread hold"],
            run: .stage("KERNEL")
        ),
        ChainDefinition(
            id: "pathtest",
            title: "PATH SCORECARD",
            subtitle: "LabPathTest per-path oracles",
            steps: ["path scorecard"],
            run: .catalog("pathtest")
        ),
        ChainDefinition(
            id: "krw",
            title: "T1 SKU DOOR",
            subtitle: "KRWChainController (catalog id krw)",
            steps: ["T1 SKU door"],
            run: .catalog("krw")
        ),
        ChainDefinition(
            id: "lightsword",
            title: "LightSword",
            subtitle: "LightSword full chain (alias luminakrw hidden)",
            steps: ["LightSword"],
            run: .catalog("lightsword")
        ),
        ChainDefinition(
            id: "swordchain",
            title: "SwordChain265",
            subtitle: "P125 one-click KRW test",
            steps: ["SwordChain"],
            run: .catalog("swordchain")
        ),
        ChainDefinition(
            id: "p044chain",
            title: "P044 → ANE254",
            subtitle: "ANE254ChainController",
            steps: ["P044", "ANE254"],
            run: .catalog("p044chain")
        ),
    ]
}

struct ChainsTabView: View {
    @Environment(LuminaAppStore.self) private var store
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var chains: [ChainDefinition] = LuminaChainCatalog.seed
    @State private var draggingStep: String?
    @State private var draggingChainId: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Chains")
                    .font(.largeTitle.bold())
                    .padding(.top, 8)

                ForEach(Array(chains.enumerated()), id: \.element.id) { index, chain in
                    chainCard(chain, index: index)
                }
            }
            .padding(16)
            .padding(.bottom, LuminaV2Theme.chipClearance + LuminaV2Theme.tabBarHeight)
        }
    }

    private func chainCard(_ chain: ChainDefinition, index: Int) -> some View {
        let active = isActive(chain)
        let states = store.rungStates(for: chain.steps, chainId: chain.id, active: active)
        let progressLabel = store.rungProgressLabel(states: states)

        return VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(chain.title)
                        .font(.headline)
                    Text(statusLine(for: chain, active: active, progress: progressLabel, states: states))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(active ? LuminaV2Theme.accent : statusColor(states: states, active: active))
                }
                Spacer()
                Button {
                    run(chain)
                } label: {
                    Label("Run chain", systemImage: "play.fill")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .frame(minHeight: 44)
                        .background(Capsule(style: .continuous).fill(LuminaV2Theme.accent))
                }
                .buttonStyle(PressableScaleButtonStyle(reduceMotion: reduceMotion, pressedScale: 0.96))
                .sensoryFeedback(.impact(flexibility: .solid), trigger: store.activeRunId == chain.id)
                .disabled(store.isRunning)
                .opacity(store.isRunning ? 0.5 : 1)
                .accessibilityLabel("Run \(chain.title)")
            }

            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(chain.steps.enumerated()), id: \.offset) { idx, step in
                    let state = idx < states.count ? states[idx] : .pending
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: "line.3.horizontal")
                            .font(.caption.weight(.bold))
                            .foregroundStyle(.secondary)
                            .frame(width: 18, height: 44)
                            .contentShape(Rectangle())
                            .onLongPressGesture(minimumDuration: 0.25) {
                                draggingStep = step
                                draggingChainId = chain.id
                            }

                        VStack(spacing: 0) {
                            Image(systemName: state.symbol)
                                .foregroundStyle(state.color)
                                .font(.body)
                            if idx < chain.steps.count - 1 {
                                Rectangle()
                                    .fill(state.color.opacity(0.45))
                                    .frame(width: 2, height: 22)
                            }
                        }
                        .frame(width: 24)

                        Text(step)
                            .font(.subheadline.monospaced())
                            .foregroundStyle(.primary)
                            .frame(minHeight: 44, alignment: .leading)
                        Spacer()
                        Text(state.label)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(state.color)
                    }
                    .padding(.vertical, 2)
                    .opacity(draggingStep == step && draggingChainId == chain.id ? 0.55 : 1)
                    .onDrop(of: [UTType.text], delegate: StepDropDelegate(
                        chainId: chain.id,
                        targetStep: step,
                        chains: $chains,
                        draggingStep: $draggingStep,
                        draggingChainId: $draggingChainId,
                        reduceMotion: reduceMotion
                    ))
                    .onDrag {
                        draggingStep = step
                        draggingChainId = chain.id
                        return NSItemProvider(object: step as NSString)
                    }
                }
            }

            Text("Hold a step to change the order")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(16)
        .luminaCard()
    }

    private func isActive(_ chain: ChainDefinition) -> Bool {
        guard store.isRunning else { return false }
        if store.activeRunId == chain.id || store.activeRunId == chain.title { return true }
        if case .catalog(let id) = chain.run, store.activeRunId == id { return true }
        if case .stage(let s) = chain.run, store.activeRunId == s { return true }
        if chain.id == "full" && (store.fullChainActive || store.activeRunId == "FULL CHAIN") { return true }
        return false
    }

    private func run(_ chain: ChainDefinition) {
        store.selectedTab = .chains
        switch chain.run {
        case .fullChain:
            store.runFullChain()
        case .stage(let s):
            store.runStage(s, displayName: chain.title)
        case .catalog(let id):
            store.runCatalogId(id)
        }
    }

    private func statusLine(
        for chain: ChainDefinition,
        active: Bool,
        progress: String,
        states: [LuminaAppStore.RungUIState]
    ) -> String {
        if active { return "running… · \(progress)" }
        if let pinned = store.pinnedSummary, matchesPinned(chain, pinned) {
            return String(format: "last · %@ · %.2fs · %@", pinned.status.rawValue, pinned.duration, progress)
        }
        if states.contains(where: { $0 != .pending }) {
            return "last · \(progress)"
        }
        return "last · not run yet"
    }

    private func statusColor(states: [LuminaAppStore.RungUIState], active: Bool) -> Color {
        if active { return LuminaV2Theme.accent }
        if states.contains(.gated) { return LuminaV2Theme.amber }
        if states.contains(.failed) { return LuminaV2Theme.danger }
        if !states.isEmpty && states.allSatisfy({ $0 == .ok }) { return LuminaV2Theme.ok }
        return .secondary
    }

    private func matchesPinned(_ chain: ChainDefinition, _ p: RunSummary) -> Bool {
        if p.catalogId == chain.id { return true }
        if case .catalog(let id) = chain.run, p.catalogId == id { return true }
        if case .stage(let s) = chain.run, p.catalogId == s { return true }
        if chain.id == "full", p.catalogId == "FULL CHAIN" { return true }
        return false
    }
}

private struct StepDropDelegate: DropDelegate {
    let chainId: String
    let targetStep: String
    @Binding var chains: [ChainDefinition]
    @Binding var draggingStep: String?
    @Binding var draggingChainId: String?
    var reduceMotion: Bool = false

    func performDrop(info: DropInfo) -> Bool {
        defer {
            draggingStep = nil
            draggingChainId = nil
        }
        guard draggingChainId == chainId,
              let from = draggingStep,
              let cIdx = chains.firstIndex(where: { $0.id == chainId }),
              let fromIdx = chains[cIdx].steps.firstIndex(of: from),
              let toIdx = chains[cIdx].steps.firstIndex(of: targetStep),
              fromIdx != toIdx
        else { return false }
        var steps = chains[cIdx].steps
        steps.move(fromOffsets: IndexSet(integer: fromIdx), toOffset: toIdx > fromIdx ? toIdx + 1 : toIdx)
        chains[cIdx].steps = steps
        return true
    }

    func dropEntered(info: DropInfo) {
        guard draggingChainId == chainId,
              let from = draggingStep,
              let cIdx = chains.firstIndex(where: { $0.id == chainId }),
              let fromIdx = chains[cIdx].steps.firstIndex(of: from),
              let toIdx = chains[cIdx].steps.firstIndex(of: targetStep),
              fromIdx != toIdx
        else { return }
        withAnimation(LuminaV2Theme.spring(reduceMotion: reduceMotion)) {
            var steps = chains[cIdx].steps
            steps.move(fromOffsets: IndexSet(integer: fromIdx), toOffset: toIdx > fromIdx ? toIdx + 1 : toIdx)
            chains[cIdx].steps = steps
            draggingStep = targetStep
        }
    }
}

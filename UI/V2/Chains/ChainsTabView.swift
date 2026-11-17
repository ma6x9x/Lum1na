//
//  ChainsTabView.swift
//  Lum1na — real sequencers only (no invented probe names).
//

import SwiftUI

struct ChainDefinition: Identifiable {
    let id: String
    let title: String
    let subtitle: String
    let steps: [String]
    let run: RunKind

    enum RunKind {
        case stage(String)
        case catalog(String)
        case fullChain
    }
}

enum LuminaChainCatalog {
    static let all: [ChainDefinition] = [
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

    var body: some View {
        NavigationStack {
            ZStack {
                LuminaV2Theme.canvas.ignoresSafeArea()
                ScrollView {
                    VStack(spacing: 16) {
                        ForEach(LuminaChainCatalog.all) { chain in
                            chainCard(chain)
                        }
                    }
                    .padding(16)
                }
            }
            .navigationTitle("Chains")
        }
    }

    private func chainCard(_ chain: ChainDefinition) -> some View {
        let active = store.isRunning && (store.activeRunId == chain.id
            || store.activeRunId == chain.title
            || (chain.run.isCatalogId.map { store.activeRunId == $0 } ?? false)
            || (chain.id == "full" && store.fullChainActive))

        return VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(chain.title)
                        .font(.headline)
                    Text(statusLine(for: chain, active: active))
                        .font(.caption.monospaced())
                        .foregroundStyle(active ? LuminaV2Theme.accent : .secondary)
                }
                Spacer()
                Button {
                    run(chain)
                } label: {
                    Label("Run chain", systemImage: "play.fill")
                        .font(.subheadline.weight(.semibold))
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                }
                .buttonStyle(.borderedProminent)
                .tint(LuminaV2Theme.accent)
                .disabled(store.isRunning)
                .accessibilityLabel("Run \(chain.title)")
            }

            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(chain.steps.enumerated()), id: \.offset) { idx, step in
                    HStack(alignment: .top, spacing: 12) {
                        VStack(spacing: 0) {
                            rungIcon(for: chain, index: idx, active: active)
                            if idx < chain.steps.count - 1 {
                                Rectangle()
                                    .fill(rungColor(for: chain, index: idx, active: active).opacity(0.5))
                                    .frame(width: 2, height: 22)
                            }
                        }
                        .frame(width: 24)
                        Text(step)
                            .font(.subheadline.monospaced())
                            .foregroundStyle(.primary)
                        Spacer()
                        Text(rungLabel(for: chain, index: idx, active: active))
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(rungColor(for: chain, index: idx, active: active))
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .padding(16)
        .luminaCard()
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

    private func statusLine(for chain: ChainDefinition, active: Bool) -> String {
        if active { return "running…" }
        if let pinned = store.pinnedSummary, pinned.catalogId == chain.id || pinned.displayName == chain.title {
            return String(format: "last · %@ · %.2fs", pinned.status.rawValue, pinned.duration)
        }
        return "last · not run yet"
    }

    private func rungIcon(for chain: ChainDefinition, index: Int, active: Bool) -> some View {
        let color = rungColor(for: chain, index: index, active: active)
        let name: String
        if active && index == 0 { name = "circle.fill" }
        else if !active && store.pinnedSummary?.status == .ok && matchesPinned(chain) { name = "checkmark.circle.fill" }
        else { name = "circle" }
        return Image(systemName: name)
            .foregroundStyle(color)
            .font(.body)
    }

    private func rungLabel(for chain: ChainDefinition, index: Int, active: Bool) -> String {
        if active && index == 0 { return "running…" }
        if matchesPinned(chain), store.pinnedSummary?.status == .ok { return "ok" }
        if matchesPinned(chain), store.pinnedSummary?.status == .gated { return "ARM-GATED" }
        return "pending"
    }

    private func rungColor(for chain: ChainDefinition, index: Int, active: Bool) -> Color {
        if active && index == 0 { return LuminaV2Theme.accent }
        if matchesPinned(chain), store.pinnedSummary?.status == .ok { return LuminaV2Theme.ok }
        if matchesPinned(chain), store.pinnedSummary?.status == .gated { return LuminaV2Theme.amber }
        return LuminaV2Theme.pending
    }

    private func matchesPinned(_ chain: ChainDefinition) -> Bool {
        guard let p = store.pinnedSummary else { return false }
        if p.catalogId == chain.id { return true }
        if case .catalog(let id) = chain.run, p.catalogId == id { return true }
        if chain.id == "full", p.catalogId == "FULL CHAIN" { return true }
        return false
    }
}

private extension ChainDefinition.RunKind {
    var isCatalogId: String? {
        if case .catalog(let id) = self { return id }
        return nil
    }
}

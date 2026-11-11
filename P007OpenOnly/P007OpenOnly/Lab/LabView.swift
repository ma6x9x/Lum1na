import SwiftUI
import UIKit

extension Reach {
    var tint: Color {
        switch self {
        case .inProcess: return T.good
        case .systemProcess: return T.info
        case .kernel: return T.bad
        case .entitlementGated: return T.warn
        case .radio: return T.violet
        case .peripheral: return T.emberSoft
        }
    }
}

extension PrimitiveKind {
    var tint: Color {
        switch self {
        case .oobWrite: return T.ember
        case .oobRead: return T.warn
        case .uaf: return T.bad
        case .infoLeak: return T.violet
        case .typeConfusion: return T.info
        case .intOverflow: return T.emberSoft
        case .probe: return Color.secondary
        }
    }

    var symbol: String {
        switch self {
        case .oobWrite: return "square.and.pencil"
        case .oobRead: return "eye"
        case .uaf: return "timer"
        case .infoLeak: return "dot.radiowaves.right"
        case .typeConfusion: return "questionmark.square"
        case .intOverflow: return "plus.forwardslash.minus"
        case .probe: return "scope"
        }
    }
}

extension LabVerdict {
    var tint: Color {
        switch self {
        case .untested: return Color.secondary
        case .running: return T.info
        case .completed: return T.good
        case .refused: return T.warn
        case .processDied: return T.ember
        }
    }
}

// MARK: - Module detail

struct ModuleDetailView: View {
    let module: ExploitModule
    @EnvironmentObject private var engine: LabEngine
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    Card {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(spacing: 6) {
                                Pill(text: module.primitive.label, color: module.primitive.tint)
                                Pill(text: module.reach.label, color: module.reach.tint)
                                Pill(text: "T\(module.tier)", color: .white.opacity(0.5))
                            }
                            Text(module.title)
                                .font(.system(size: 19, weight: .bold, design: .rounded))
                                .foregroundColor(.white)
                            Text(module.component)
                                .font(T.mono)
                                .foregroundColor(.white.opacity(0.4))
                            Text(module.cve)
                                .font(T.mono)
                                .foregroundColor(T.emberSoft)
                        }
                    }

                    Card {
                        VStack(alignment: .leading, spacing: 8) {
                            SectionLabel(text: t("module.primitive"))
                            Text(module.summary)
                                .font(T.body)
                                .foregroundColor(.white.opacity(0.8))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    Card {
                        VStack(alignment: .leading, spacing: 8) {
                            SectionLabel(text: t("module.notes"))
                            Text(module.notes)
                                .font(T.body)
                                .foregroundColor(.white.opacity(0.65))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    if let outcome = engine.outcome(for: module.id) {
                        Card {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    SectionLabel(text: t("module.result"))
                                    Spacer()
                                    Text("\(outcome.elapsedMs) ms").font(T.monoSm).foregroundColor(.white.opacity(0.3))
                                    Button {
                                        LuminaCopyBus.shared.copy(
                                            LabLogStore.readFull(id: module.id)
                                            ?? outcome.copyBlock(moduleId: module.id),
                                            label: "Full log copied")
                                    } label: {
                                        Label("Copy full", systemImage: "doc.on.doc")
                                            .font(.system(size: 11, weight: .semibold))
                                    }
                                    .tint(T.ember)
                                }
                                Text(outcome.headline)
                                    .font(.system(size: 15, weight: .semibold, design: .rounded))
                                    .foregroundColor(outcome.failed ? T.bad : T.good)
                                    .textSelection(.enabled)
                                if !outcome.detail.isEmpty {
                                    let shown = outcome.detail.count > 4000
                                        ? String(outcome.detail.prefix(4000)) + "\n…[Copy full]"
                                        : outcome.detail
                                    Text(shown)
                                        .font(T.monoSm)
                                        .foregroundColor(.white.opacity(0.6))
                                        .fixedSize(horizontal: false, vertical: true)
                                        .textSelection(.enabled)
                                }
                                ForEach(Array(outcome.evidence.prefix(40).enumerated()), id: \.offset) { _, line in
                                    Text("· \(line)")
                                        .font(T.monoSm)
                                        .foregroundColor(.white.opacity(0.42))
                                        .lineLimit(4)
                                        .textSelection(.enabled)
                                }
                                Text("Full log: Documents/lum1na/\(LabLogStore.safeId(module.id))_log.txt  ·  Console → folder")
                                    .font(T.tiny)
                                    .foregroundColor(.white.opacity(0.35))
                            }
                        }
                    }

                    let history = engine.journal.history(for: module.id)
                    if !history.isEmpty {
                        Card {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    SectionLabel(text: t("module.history"))
                                    Spacer()
                                    Button("Copy") {
                                        let block = history.map { "\($0.phase)\t\($0.detail)" }.joined(separator: "\n")
                                        LuminaCopyBus.shared.copy(block, label: "History copied")
                                    }
                                    .font(.system(size: 11, weight: .semibold))
                                    .tint(T.ember)
                                }
                                ForEach(history.suffix(8)) { entry in
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(entry.phase)
                                            .font(T.monoSm)
                                            .foregroundColor(entry.phase == "died" ? T.ember : .white.opacity(0.4))
                                        Text(entry.detail)
                                            .font(T.monoSm)
                                            .foregroundColor(.white.opacity(0.35))
                                            .lineLimit(3)
                                            .textSelection(.enabled)
                                    }
                                }
                            }
                        }
                    }

                    RunButton(title: engine.running.contains(module.id) ? t("module.running") : t("module.run"),
                              systemImage: "bolt.fill",
                              tint: module.primitive.tint,
                              disabled: engine.running.contains(module.id)) {
                        engine.run(module)
                    }

                    Text(t("module.warning"))
                        .font(T.tiny)
                        .foregroundColor(.white.opacity(0.32))
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(16)
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(t("tab.lab"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(t("module.close")) { dismiss() }.tint(T.ember)
                }
            }
        }
    }
}

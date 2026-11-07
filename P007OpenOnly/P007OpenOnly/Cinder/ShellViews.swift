//
//  ShellViews.swift — Tests index, More hub, Console peek.
//
//  The catalog is the single place every test lives: rich modules plus
//  the 186-id dispatcher directory (Catalog.tapDirectory). Search is the
//  fast path; the tab bar is the short path to Console.
//

import SwiftUI
import UIKit

// MARK: - Tests (searchable catalog)

struct TestsView: View {
    @EnvironmentObject private var engine: LabEngine
    @State private var query = ""
    @State private var untestedOnly = false
    @State private var selected: ExploitModule?

    private var searchedGroups: [(String, [ExploitModule])] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return Catalog.groups }
        let hits = Catalog.all.filter { m in
            m.id.lowercased().contains(q)
                || m.title.lowercased().contains(q)
                || m.component.lowercased().contains(q)
                || m.cve.lowercased().contains(q)
        }
        return hits.isEmpty ? [] : [("Matches · \(hits.count)", hits)]
    }

    private var groups: [(String, [ExploitModule])] {
        guard untestedOnly else { return searchedGroups }
        return searchedGroups.compactMap { name, mods in
            let fresh = mods.filter { engine.journal.verdict(for: $0.id) == .untested }
            return fresh.isEmpty ? nil : (name, fresh)
        }
    }

    private var testedCount: Int {
        Catalog.all.filter { engine.journal.verdict(for: $0.id) != .untested }.count
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVStack(spacing: 14) {
                    HStack(spacing: 8) {
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(.white.opacity(0.4))
                        TextField("id, title, component, CVE", text: $query)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundColor(.white.opacity(0.9))
                        if !query.isEmpty {
                            Button {
                                query = ""
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundColor(.white.opacity(0.35))
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(T.panel)
                    }
                    .overlay {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .strokeBorder(T.cyan.opacity(0.18), lineWidth: 1)
                    }

                    HStack(spacing: 10) {
                        statChip("\(Catalog.all.count)", "modules", T.info)
                        statChip("\(testedCount)", "tested", T.warn)
                        Spacer(minLength: 0)
                        Button {
                            untestedOnly.toggle()
                        } label: {
                            Pill(text: "untested only",
                                 color: untestedOnly ? T.warn : .white.opacity(0.4))
                        }
                        .buttonStyle(.plain)
                    }

                    if groups.isEmpty {
                        Card {
                            VStack(alignment: .leading, spacing: 6) {
                                SectionLabel(text: "No match")
                                Text("Nothing matches \(query). Every TAP id is in the All TAPs group — clear the query and scroll, or search by id (e.g. p150, p152, p044).")
                                    .font(T.body)
                                    .foregroundColor(.white.opacity(0.7))
                            }
                        }
                    }

                    ForEach(groups, id: \.0) { group in
                        VStack(alignment: .leading, spacing: 8) {
                            SectionLabel(text: group.0)
                            ForEach(group.1) { module in
                                Button {
                                    selected = module
                                } label: {
                                    testRow(module)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
                .padding(16)
            }
            .luminaCanvas()
            .navigationTitle("Tests")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Text("\(Catalog.all.count)")
                        .font(T.monoSm)
                        .foregroundColor(.white.opacity(0.4))
                }
            }
            .sheet(item: $selected) { module in
                ModuleDetailView(module: module)
                    .environmentObject(engine)
                    .presentationDetents([.large])
            }
        }
    }

    private func statChip(_ value: String, _ label: String, _ color: Color) -> some View {
        HStack(spacing: 4) {
            Text(value)
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(color)
            Text(label)
                .font(T.tiny)
                .foregroundColor(.white.opacity(0.4))
        }
    }

    private static let chainIDs: Set<String> =
        Set(ChainPlan.stages.flatMap { $0.moduleIDs })

    private func testRow(_ module: ExploitModule) -> some View {
        let verdict = engine.journal.verdict(for: module.id)
        let running = engine.running.contains(module.id)
        return HStack(alignment: .top, spacing: 10) {
            RoundedRectangle(cornerRadius: 2)
                .fill(running ? T.info : verdict.tint)
                .frame(width: 3)
            VStack(alignment: .leading, spacing: 5) {
                Text(module.title)
                    .font(.system(size: 13, weight: .semibold, design: .rounded))
                    .foregroundColor(.white.opacity(0.92))
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
                HStack(spacing: 6) {
                    Text(module.id)
                        .font(T.monoSm)
                        .foregroundColor(T.cyan.opacity(0.8))
                    Pill(text: module.primitive.label, color: module.primitive.tint)
                    if Self.chainIDs.contains(module.id) {
                        Pill(text: "chain", color: T.ember)
                    }
                    Text("T\(module.tier)")
                        .font(T.monoSm)
                        .foregroundColor(.white.opacity(0.3))
                    Spacer(minLength: 0)
                    if running { ProgressView().scaleEffect(0.55) }
                    else { Pill(text: t(verdict.key), color: verdict.tint) }
                }
            }
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background {
            RoundedRectangle(cornerRadius: 12, style: .continuous).fill(T.panel)
        }
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(verdict.tint.opacity(0.18), lineWidth: 1)
        }
    }
}

// MARK: - More (everything that used to be its own tab)

struct MoreView: View {
    var body: some View {
        NavigationStack {
            List {
                Section("Campaign") {
                    NavigationLink("Overview / stats") { DashboardView() }
                    NavigationLink("Chain plan") { ChainView() }
                }
                Section("Panes") {
                    NavigationLink("Files & knobs (Mod)") { ModView() }
                    NavigationLink("Mind") { MindPane() }
                    NavigationLink("System") { SystemView() }
                }
                Section("Notes") {
                    Text("Tests and Lab share one catalog and one dispatcher. Console is always one tap away on the tab bar; the peek above it shows the latest line.")
                        .font(T.tiny)
                        .foregroundColor(.white.opacity(0.55))
                }
            }
            .scrollContentBackground(.hidden)
            .background(T.void)
            .navigationTitle("More")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

// MARK: - Console peek (latest line, tap to open Console)

struct ConsolePeek: View {
    @EnvironmentObject private var engine: LabEngine

    private var lastLine: String {
        let l = engine.logLines.last ?? "no log yet — the console keeps every TAP body"
        return String(l.suffix(96))
    }

    var body: some View {
        Button {
            LuminaTabs.shared.index = 4
        } label: {
            HStack(spacing: 8) {
                Image(systemName: "terminal.fill")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(T.cyan)
                Text(lastLine)
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundColor(.white.opacity(0.72))
                    .lineLimit(1)
                Spacer(minLength: 6)
                Text("Console")
                    .font(.system(size: 10, weight: .semibold, design: .rounded))
                    .foregroundColor(T.cyan)
                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundColor(T.cyan.opacity(0.6))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .luminaGlass(Capsule(), interactive: true, tint: T.violet)
            .padding(.horizontal, 12)
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Open Console")
    }
}

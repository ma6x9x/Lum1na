//
//  ShellViews.swift — Tests index, More hub, Console peek.
//
//  The catalog is the single place every test lives: rich modules plus
//  the dispatcher directory, split into TapDirectory letter groups.
//  Tests and Lab share CatalogBrowser. Search keeps sections. The
//  section menu jumps. The tab bar is the short path to Console.
//

import SwiftUI
import UIKit

// MARK: - Shared catalog row (inset list, not a card per test)

struct ModuleListRow: View {
    let title: String
    let detail: String
    let systemImage: String
    let verdictText: String
    let verdictTint: Color
    let running: Bool
    var badge: String? = nil

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(verdictTint)
                .frame(width: 32, height: 32)
                .background(verdictTint.opacity(0.16), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 15, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Text(detail)
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            Spacer(minLength: 8)
            if let badge, !badge.isEmpty {
                Text(badge)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(T.accent)
            }
            if running {
                ProgressView()
            } else {
                Text(verdictText)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(verdictTint)
                    .lineLimit(1)
            }
            Image(systemName: "chevron.right")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
        .frame(minHeight: 44)
        .contentShape(Rectangle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title), \(badge.map { $0 + ", " } ?? "")\(verdictText)")
        .accessibilityHint(String(detail.prefix(96)))
    }
}

// MARK: - Tests

struct TestsView: View {
    var body: some View {
        CatalogBrowser(title: "Tests", showsFilter: true)
    }
}

// MARK: - Shared catalog browser
//
// One list for Tests and Lab. Sections stay put while searching, so a hit
// keeps its group. The menu scrolls to the first row of a section.

struct CatalogBrowser: View {
    @EnvironmentObject private var engine: LabEngine
    let title: String
    var showsFilter: Bool = false
    var showsCopy: Bool = false

    @State private var query = ""
    @State private var filter: TestFilter = .all
    @State private var selected: ExploitModule?

    private enum TestFilter: String, CaseIterable, Identifiable {
        case all, untested, chain
        var id: String { rawValue }
        var title: String {
            switch self {
            case .all: return "All"
            case .untested: return "Untested"
            case .chain: return "Chain"
            }
        }
    }

    private static let chainIDs: Set<String> =
        Set(ChainPlan.stages.flatMap { $0.moduleIDs })

    var body: some View {
        let sections = visibleSections
        let shown = sections.reduce(0) { $0 + $1.1.count }
        NavigationStack {
            Group {
                if sections.isEmpty {
                    emptyState
                } else {
                    catalogList(sections)
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .searchable(text: $query, prompt: "Id, name, CVE, or group")
            .toolbar {
                ToolbarItem(placement: .principal) {
                    VStack(spacing: 1) {
                        Text(title)
                            .font(.system(size: 17, weight: .semibold))
                        Text("\(shown) of \(Catalog.all.count)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("\(title), \(shown) of \(Catalog.all.count) tests")
                }
                if showsFilter {
                    ToolbarItem(placement: .topBarTrailing) {
                        Menu {
                            Picker("Show", selection: $filter) {
                                ForEach(TestFilter.allCases) { item in
                                    Text(item.title).tag(item)
                                }
                            }
                        } label: {
                            Label(filter == .all ? "Filter" : filter.title,
                                  systemImage: "line.3.horizontal.decrease")
                        }
                        .accessibilityLabel("Filter tests")
                    }
                }
                if showsCopy {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Copy all") {
                            LuminaCopyBus.shared.copy(engine.copyAllResults(), label: "All logs copied")
                        }
                    }
                }
            }
            .sheet(item: $selected) { module in
                ModuleDetailView(module: module)
                    .environmentObject(engine)
                    .presentationDetents([.large])
                    .presentationDragIndicator(.visible)
            }
        }
    }

    private var emptyState: some View {
        Group {
            if query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                ContentUnavailableView(
                    "Nothing in \(filter.title)",
                    systemImage: "line.3.horizontal.decrease.circle",
                    description: Text("Switch the filter back to All."))
            } else {
                ContentUnavailableView.search(text: query)
            }
        }
    }

    private func catalogList(_ sections: [(String, [ExploitModule])]) -> some View {
        ScrollViewReader { proxy in
            List {
                ForEach(sections, id: \.0) { group in
                    Section("\(group.0) · \(group.1.count)") {
                        ForEach(Array(group.1.enumerated()), id: \.element.id) { index, module in
                            Button {
                                selected = module
                            } label: {
                                catalogRow(module)
                            }
                            .buttonStyle(.plain)
                            .id(index == 0 ? sectionAnchor(group.0) : rowAnchor(module.id))
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        ForEach(sections, id: \.0) { group in
                            Button {
                                proxy.scrollTo(sectionAnchor(group.0), anchor: .top)
                            } label: {
                                Text("\(group.0)  \(group.1.count)")
                            }
                        }
                    } label: {
                        Label("Sections", systemImage: "list.bullet")
                    }
                    .accessibilityLabel("Jump to section")
                }
            }
        }
    }

    /// Filter first, then keep any section that matches the query or still
    /// holds a matching module. Search does not flatten the catalog.
    private var visibleSections: [(String, [ExploitModule])] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return Catalog.groups.compactMap { name, mods in
            let filtered = mods.filter { module in
                guard showsFilter else { return true }
                switch filter {
                case .all: return true
                case .untested: return engine.journal.verdict(for: module.id) == .untested
                case .chain: return Self.chainIDs.contains(module.id)
                }
            }
            guard !filtered.isEmpty else { return nil }
            guard !q.isEmpty else { return (name, filtered) }
            if name.lowercased().contains(q) { return (name, filtered) }
            let hits = filtered.filter { matches($0, q) }
            return hits.isEmpty ? nil : (name, hits)
        }
    }

    private func matches(_ module: ExploitModule, _ q: String) -> Bool {
        module.id.lowercased().contains(q)
            || module.title.lowercased().contains(q)
            || module.component.lowercased().contains(q)
            || module.cve.lowercased().contains(q)
            || module.primitive.label.lowercased().contains(q)
            || module.primitive.rawValue.lowercased().contains(q)
            || module.reach.label.lowercased().contains(q)
            || module.reach.rawValue.lowercased().contains(q)
    }

    private func catalogRow(_ module: ExploitModule) -> some View {
        let verdict = engine.journal.verdict(for: module.id)
        let badge = Self.chainIDs.contains(module.id) ? "chain" : nil
        return ModuleListRow(
            title: module.id,
            detail: module.title,
            systemImage: module.primitive.symbol,
            verdictText: t(verdict.key),
            verdictTint: verdict.tint,
            running: engine.running.contains(module.id),
            badge: badge)
    }

    private func sectionAnchor(_ name: String) -> String { "catalog-section:\(name)" }
    private func rowAnchor(_ id: String) -> String { "catalog-row:\(id)" }
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
                    Text("Tests and Lab share one catalog. The list menu jumps to a section, and search matches id, name, CVE, or group. Console stays on the tab bar.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .listStyle(.insetGrouped)
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
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Spacer(minLength: 6)
                Text("Console")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(T.accent)
                Image(systemName: "chevron.right")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 14)
            .frame(minHeight: 44)
            .luminaGlass(Capsule(), interactive: true)
            .padding(.horizontal, 16)
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Open Console")
    }
}

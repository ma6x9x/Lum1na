//
//  ShellViews.swift — Tests index, More hub, Console peek.
//
//  Tests is the only catalog. Search, filter, and the section menu live
//  in the page, under the HUD. The navigation bar sits behind that HUD,
//  so it is not used here.
//

import SwiftUI
import UIKit

// MARK: - Shared catalog row (inset list, not a card per test)

struct ModuleListRow: View {
    let title: String
    let detail: String
    let verdictText: String
    let verdictTint: Color
    let running: Bool
    var badge: String? = nil

    var body: some View {
        HStack(spacing: 12) {
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
// Sections stay put while searching. The section menu scrolls to the
// first row of a group. Controls are in the page, not the hidden bar.

struct CatalogBrowser: View {
    @EnvironmentObject private var engine: LabEngine
    let title: String
    var showsFilter: Bool = false

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
        ScrollViewReader { proxy in
            VStack(spacing: 0) {
                header(shown: shown, sections: sections, proxy: proxy)
                searchField
                Group {
                    if sections.isEmpty {
                        emptyState
                    } else {
                        catalogList(sections)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .background(Color(.systemGroupedBackground))
        }
        .sheet(item: $selected) { module in
            ModuleDetailView(module: module)
                .environmentObject(engine)
                .presentationDetents([.large])
                .presentationDragIndicator(.visible)
        }
    }

    private func header(shown: Int,
                        sections: [(String, [ExploitModule])],
                        proxy: ScrollViewProxy) -> some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.system(size: 22, weight: .bold))
                Text("\(shown) of \(Catalog.all.count)")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 8)
            if showsFilter {
                Menu {
                    Picker("Show", selection: $filter) {
                        ForEach(TestFilter.allCases) { item in
                            Text(item.title).tag(item)
                        }
                    }
                } label: {
                    Label(filter == .all ? "Filter" : filter.title,
                          systemImage: "line.3.horizontal.decrease")
                        .font(.system(size: 14, weight: .semibold))
                        .padding(.horizontal, 12)
                        .frame(minHeight: 44)
                }
                .catalogMenuChrome()
                .accessibilityLabel("Filter tests")
            }
            if !sections.isEmpty {
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
                        .font(.system(size: 14, weight: .semibold))
                        .padding(.horizontal, 12)
                        .frame(minHeight: 44)
                }
                .catalogMenuChrome()
                .accessibilityLabel("Jump to section")
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 6)
        .padding(.bottom, 8)
    }

    private var searchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
            TextField("Id, name, CVE, or group", text: $query)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            if !query.isEmpty {
                Button {
                    query = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear search")
            }
        }
        .padding(.horizontal, 12)
        .frame(minHeight: 44)
        .background(T.panel, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
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
        List {
            ForEach(sections, id: \.0) { group in
                Section {
                    ForEach(Array(group.1.enumerated()), id: \.element.id) { index, module in
                        Button {
                            selected = module
                        } label: {
                            catalogRow(module)
                        }
                        .buttonStyle(.plain)
                        .id(index == 0 ? sectionAnchor(group.0) : rowAnchor(module.id))
                    }
                } header: {
                    Text("\(group.0) · \(group.1.count)")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.secondary)
                        .textCase(nil)
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollDismissesKeyboard(.interactively)
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
            verdictText: t(verdict.key),
            verdictTint: verdict.tint,
            running: engine.running.contains(module.id),
            badge: badge)
    }

    private func sectionAnchor(_ name: String) -> String { "catalog-section:\(name)" }
    private func rowAnchor(_ id: String) -> String { "catalog-row:\(id)" }
}

extension View {
    /// Real menu chrome. Xcode 26 compiles the glass pill; Xcode 16.4 keeps
    /// a bordered menu that still opens. The label stays a 44-pt target.
    @ViewBuilder
    func catalogMenuChrome() -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26.0, *) {
            self.buttonStyle(.glass)
        } else {
            self.buttonStyle(.bordered)
        }
        #else
        self.buttonStyle(.bordered)
        #endif
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
                    Text("Tests is the only catalog. Its search box and Sections menu stay on that page. Console is the log and the four hunt buttons.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .listStyle(.insetGrouped)
            .safeAreaInset(edge: .top, spacing: 0) {
                Text("More")
                    .font(.system(size: 22, weight: .bold))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 20)
                    .padding(.top, 4)
                    .padding(.bottom, 6)
            }
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

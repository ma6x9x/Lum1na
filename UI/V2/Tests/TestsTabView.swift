//
//  TestsTabView.swift
//  Lum1na — searchable grouped Probes/Taps/Chains/Kernel reads.
//

import SwiftUI

struct TestsTabView: View {
    @Environment(LuminaAppStore.self) private var store
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var knobEntryId: String?
    @State private var knobEntryName = ""
    @State private var knubText = ""
    @State private var showKnobAlert = false

    var body: some View {
        @Bindable var store = store
        NavigationStack {
            ZStack(alignment: .bottom) {
                LuminaV2Theme.canvas.ignoresSafeArea()

                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        DeviceHeaderBar()
                            .padding(.top, 4)

                        HStack(spacing: 10) {
                            Image(systemName: "magnifyingglass")
                                .foregroundStyle(.secondary)
                            TextField("Search tests and probes", text: $store.searchText)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        }
                        .padding(12)
                        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 14, style: .continuous))

                        ForEach(store.groupedCatalog(matching: store.searchText), id: \.0) { group, entries in
                            groupCard(group, entries: entries)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.bottom, store.pinnedSummary == nil || store.showResultsSheet ? 24 : 100)
                }

                if let summary = store.pinnedSummary, !store.showResultsSheet {
                    PinnedSummaryChip(summary: summary) {
                        store.activeRunId = summary.catalogId
                        store.activeRunName = summary.displayName
                        store.showResultsSheet = true
                    }
                    .padding(.horizontal, 16)
                    .padding(.bottom, 8)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .navigationTitle("Tests")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        store.showSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                            .frame(width: 44, height: 44)
                    }
                    .accessibilityLabel("Settings")
                }
            }
            .alert("Knob — \(knobEntryName)", isPresented: $showKnobAlert) {
                TextField("e.g. pid / resid / untagged", text: $knubText)
                Button("Save") {
                    if let id = knobEntryId { store.writeKnob(id: id, value: knubText) }
                }
                Button("Clear", role: .destructive) {
                    if let id = knobEntryId { store.writeKnob(id: id, value: "") }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Input value used by this test at tap time (empty = stock behavior).")
            }
            .onReceive(NotificationCenter.default.publisher(for: .luminaEditKnob)) { note in
                guard let id = note.object as? String,
                      let entry = store.catalogEntries.first(where: { $0.id == id }) else { return }
                knobEntryId = id
                knobEntryName = entry.name
                knubText = store.knobValue(id)
                showKnobAlert = true
            }
        }
    }

    @ViewBuilder
    private func groupCard(_ group: TestGroup, entries: [ExploitCatalogEntry]) -> some View {
        let expanded = store.expandedGroups.contains(group)
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(LuminaV2Theme.spring(reduceMotion: reduceMotion)) {
                    if expanded { store.expandedGroups.remove(group) }
                    else { store.expandedGroups.insert(group) }
                }
            } label: {
                HStack {
                    Image(systemName: expanded ? "chevron.down" : "chevron.right")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.secondary)
                        .frame(width: 18)
                    Text(group.rawValue)
                        .font(.headline)
                        .foregroundStyle(.primary)
                    Spacer()
                    Text("\(entries.count)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                .padding(16)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("\(group.rawValue), \(entries.count) items, \(expanded ? "expanded" : "collapsed")")

            if expanded {
                Divider().opacity(0.25)
                LazyVStack(spacing: 14) {
                    ForEach(entries) { entry in
                        TestRowView(entry: entry)
                    }
                }
                .padding(16)
            }
        }
        .luminaCard()
    }
}

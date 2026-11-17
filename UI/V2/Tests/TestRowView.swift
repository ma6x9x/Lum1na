//
//  TestRowView.swift
//  Lum1na
//

import SwiftUI

struct TestRowView: View {
    let entry: ExploitCatalogEntry
    @Environment(LuminaAppStore.self) private var store
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var meta: CatalogUIMeta { CatalogMetadata.meta(for: entry) }

    var body: some View {
        Button {
            store.requestRun(entry)
        } label: {
            HStack(alignment: .top, spacing: 12) {
                ZStack {
                    Circle()
                        .fill(LuminaV2Theme.accent.opacity(store.isRunning ? 0.25 : 0.9))
                        .frame(width: 36, height: 36)
                    Image(systemName: store.isRunning && store.activeRunId == entry.id ? "stop.fill" : "play.fill")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(.white)
                }
                .frame(width: 44, height: 44)
                .accessibilityLabel(store.isRunning && store.activeRunId == entry.id ? "Running \(meta.displayName)" : "Run \(meta.displayName)")

                VStack(alignment: .leading, spacing: 6) {
                    Text(entry.id)
                        .font(.subheadline.weight(.semibold).monospaced())
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    Text(meta.displayName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    HonestyBadgeRow(
                        badges: store.badges(for: entry),
                        compact: store.settings.compactBadges
                    )
                }
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(store.isRunning && store.activeRunId != entry.id)
        .contextMenu {
            Button {
                // open knob editor via settings-like alert handled in TestsTab
                NotificationCenter.default.post(name: .luminaEditKnob, object: entry.id)
            } label: {
                Label("Edit knob…", systemImage: "slider.horizontal.3")
            }
            Button {
                store.copyToPasteboard(entry.id)
            } label: {
                Label("Copy id", systemImage: "doc.on.doc")
            }
        }
    }
}

extension Notification.Name {
    static let luminaEditKnob = Notification.Name("luminaEditKnob")
}

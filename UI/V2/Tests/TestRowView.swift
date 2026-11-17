//
//  TestRowView.swift
//  Lum1na — id + badges only (no display-name clutter).
//

import SwiftUI

struct TestRowView: View {
    let entry: ExploitCatalogEntry
    @Environment(LuminaAppStore.self) private var store

    private var meta: CatalogUIMeta { CatalogMetadata.meta(for: entry) }

    var body: some View {
        Button {
            store.requestRun(entry)
        } label: {
            HStack(alignment: .center, spacing: 12) {
                ZStack {
                    Circle()
                        .fill(LuminaV2Theme.accent.opacity(store.isRunning && store.activeRunId == entry.id ? 0.35 : 0.9))
                        .frame(width: 36, height: 36)
                    Image(systemName: store.isRunning && store.activeRunId == entry.id ? "stop.fill" : "play.fill")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(.white)
                }
                .frame(width: 44, height: 44)
                .accessibilityLabel(store.isRunning && store.activeRunId == entry.id ? "Running \(entry.id)" : "Run \(entry.id)")

                VStack(alignment: .leading, spacing: 6) {
                    Text(entry.id)
                        .font(.subheadline.weight(.semibold).monospaced())
                        .foregroundStyle(.primary)
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
        .accessibilityHint(meta.displayName)
    }
}

extension Notification.Name {
    static let luminaEditKnob = Notification.Name("luminaEditKnob")
}

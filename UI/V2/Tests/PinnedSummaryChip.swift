//
//  PinnedSummaryChip.swift
//  Lum1na
//

import SwiftUI

struct PinnedSummaryChip: View {
    let summary: RunSummary
    var onExpand: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var statusColor: Color {
        switch summary.status {
        case .ok: return LuminaV2Theme.ok
        case .failed: return LuminaV2Theme.danger
        case .gated: return LuminaV2Theme.amber
        case .cancelled: return LuminaV2Theme.pending
        }
    }

    var body: some View {
        Button(action: onExpand) {
            HStack(spacing: 12) {
                Image(systemName: summary.status.symbol)
                    .font(.title3)
                    .foregroundStyle(statusColor)
                    .modifier(BounceIfAllowed(value: summary.id, reduceMotion: reduceMotion))
                    .frame(width: 28)

                VStack(alignment: .leading, spacing: 2) {
                    Text("\(summary.catalogId)  •  \(summary.status.rawValue)")
                        .font(.subheadline.weight(.semibold).monospaced())
                        .foregroundStyle(.primary)
                    Text(summary.keyValues.joined(separator: "  •  "))
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 4)
                Text(String(format: "%.2fs", summary.duration))
                    .font(.caption.weight(.semibold).monospacedDigit())
                    .foregroundStyle(statusColor)
                Image(systemName: "chevron.up")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .frame(minHeight: 44)
            .luminaChromeGlass(cornerRadius: 18, interactive: true)
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Pinned summary \(summary.catalogId) \(summary.status.rawValue), \(String(format: "%.2f seconds", summary.duration)). Double tap to expand.")
    }
}

private struct BounceIfAllowed: ViewModifier {
    let value: UUID
    let reduceMotion: Bool

    func body(content: Content) -> some View {
        if reduceMotion {
            content
        } else {
            content.symbolEffect(.bounce, value: value)
        }
    }
}

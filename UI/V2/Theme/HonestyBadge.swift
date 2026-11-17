//
//  HonestyBadge.swift
//  Lum1na — SF Symbol + short word; never color alone.
//

import SwiftUI

enum HonestyBadgeKind: String, Hashable, CaseIterable, Identifiable {
    case reach
    case window
    case conversion
    case hasKread
    case after
    case armGated
    case closed

    var id: String { rawValue }

    var label: String {
        switch self {
        case .reach: return "reach"
        case .window: return "window"
        case .conversion: return "→ conv"
        case .hasKread: return "hasKread"
        case .after: return "after"
        case .armGated: return "ARM-GATED"
        case .closed: return "CLOSED"
        }
    }

    var symbol: String {
        switch self {
        case .reach: return "eye"
        case .window: return "clock"
        case .conversion: return "arrow.right"
        case .hasKread: return "checkmark.circle"
        case .after: return "bolt"
        case .armGated: return "lock.fill"
        case .closed: return "xmark.octagon.fill"
        }
    }

    var accessibilityLabel: String {
        switch self {
        case .reach: return "Reach"
        case .window: return "Window"
        case .conversion: return "Conversion"
        case .hasKread: return "Has kernel read"
        case .after: return "After kread"
        case .armGated: return "ARM gated, locked"
        case .closed: return "Closed, parked"
        }
    }
}

struct HonestyBadgeView: View {
    let kind: HonestyBadgeKind
    var met: Bool = false
    var compact: Bool = false

    private var fill: Color {
        switch kind {
        case .armGated:
            return LuminaV2Theme.amber.opacity(met ? 0.28 : 0.16)
        case .closed:
            return LuminaV2Theme.danger.opacity(0.22)
        default:
            return met ? LuminaV2Theme.ok.opacity(0.22) : Color.white.opacity(0.06)
        }
    }

    private var stroke: Color {
        switch kind {
        case .armGated: return LuminaV2Theme.amber
        case .closed: return LuminaV2Theme.danger
        default: return met ? LuminaV2Theme.ok : LuminaV2Theme.pending
        }
    }

    private var foreground: Color {
        switch kind {
        case .armGated: return LuminaV2Theme.amber
        case .closed: return LuminaV2Theme.danger
        default: return met ? LuminaV2Theme.ok : LuminaV2Theme.pending
        }
    }

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: kind.symbol)
                .font(.caption2.weight(.semibold))
            Text(kind.label)
                .font(compact ? .caption2.weight(.semibold) : .caption.weight(.semibold))
        }
        .foregroundStyle(foreground)
        .padding(.horizontal, compact ? 7 : 8)
        .padding(.vertical, compact ? 3 : 4)
        .background(
            Capsule(style: .continuous)
                .fill(fill)
        )
        .overlay(
            Capsule(style: .continuous)
                .strokeBorder(
                    stroke.opacity(met || kind == .armGated || kind == .closed ? 0.9 : 0.45),
                    lineWidth: 1
                )
        )
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(kind.accessibilityLabel + (met ? ", met" : ", not met"))
    }
}

struct HonestyBadgeRow: View {
    let badges: [(HonestyBadgeKind, Bool)]
    var compact: Bool = false

    var body: some View {
        FlexibleBadgeWrap(badges: badges, compact: compact)
    }
}

/// Real wrapping layout (not two fixed HStacks).
private struct FlexibleBadgeWrap: View {
    let badges: [(HonestyBadgeKind, Bool)]
    var compact: Bool

    var body: some View {
        BadgeFlowLayout(spacing: 4) {
            ForEach(badges, id: \.0) { item in
                HonestyBadgeView(kind: item.0, met: item.1, compact: compact)
            }
        }
    }
}

private struct BadgeFlowLayout: Layout {
    var spacing: CGFloat = 4

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = computeRows(proposal: proposal, subviews: subviews)
        let width = proposal.width ?? rows.map(\.width).max() ?? 0
        let height = rows.reduce(0) { $0 + $1.height } + CGFloat(max(rows.count - 1, 0)) * spacing
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let rows = computeRows(proposal: ProposedViewSize(width: bounds.width, height: bounds.height), subviews: subviews)
        var y = bounds.minY
        var index = 0
        for row in rows {
            var x = bounds.minX
            for _ in 0..<row.count {
                let size = subviews[index].sizeThatFits(.unspecified)
                subviews[index].place(
                    at: CGPoint(x: x, y: y),
                    proposal: ProposedViewSize(size)
                )
                x += size.width + spacing
                index += 1
            }
            y += row.height + spacing
        }
    }

    private struct Row {
        var count: Int
        var width: CGFloat
        var height: CGFloat
    }

    private func computeRows(proposal: ProposedViewSize, subviews: Subviews) -> [Row] {
        let maxWidth = proposal.width ?? .infinity
        var rows: [Row] = []
        var current = Row(count: 0, width: 0, height: 0)
        for sub in subviews {
            let size = sub.sizeThatFits(.unspecified)
            let nextWidth = current.count == 0 ? size.width : current.width + spacing + size.width
            if current.count > 0, nextWidth > maxWidth {
                rows.append(current)
                current = Row(count: 1, width: size.width, height: size.height)
            } else {
                current.count += 1
                current.width = nextWidth
                current.height = max(current.height, size.height)
            }
        }
        if current.count > 0 { rows.append(current) }
        return rows
    }
}

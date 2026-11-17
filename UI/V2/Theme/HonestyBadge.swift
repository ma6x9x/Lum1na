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
            return LuminaV2Theme.amber.opacity(met || true ? 0.22 : 0.12)
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
                .font(.system(size: compact ? 9 : 10, weight: .semibold))
            Text(kind.label)
                .font(.system(size: compact ? 10 : 11, weight: .semibold, design: .rounded))
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
                .strokeBorder(stroke.opacity(met || kind == .armGated || kind == .closed ? 0.9 : 0.45), lineWidth: 1)
        )
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(kind.accessibilityLabel + (met ? ", met" : ", not met"))
    }
}

struct HonestyBadgeRow: View {
    let badges: [(HonestyBadgeKind, Bool)]
    var compact: Bool = false

    var body: some View {
        FlowHonestyBadges(badges: badges, compact: compact)
    }
}

/// Simple wrapping HStack without third-party deps.
private struct FlowHonestyBadges: View {
    let badges: [(HonestyBadgeKind, Bool)]
    var compact: Bool

    var body: some View {
        FlexibleBadgeWrap(badges: badges, compact: compact)
    }
}

private struct FlexibleBadgeWrap: View {
    let badges: [(HonestyBadgeKind, Bool)]
    var compact: Bool

    var body: some View {
        // Two-line wrap approximation: primary honesty first, gates last.
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 4) {
                ForEach(badges.filter { $0.0 != .armGated && $0.0 != .closed }, id: \.0) { item in
                    HonestyBadgeView(kind: item.0, met: item.1, compact: compact)
                }
            }
            HStack(spacing: 4) {
                ForEach(badges.filter { $0.0 == .armGated || $0.0 == .closed }, id: \.0) { item in
                    HonestyBadgeView(kind: item.0, met: item.1, compact: compact)
                }
            }
        }
    }
}

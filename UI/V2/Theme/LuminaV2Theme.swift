//
//  LuminaV2Theme.swift
//  Lum1na — v2 chrome tokens (dark-first).
//

import SwiftUI

enum LuminaV2Theme {
    static let canvas = Color(hex: "#0B0B12")
    static let canvasElevated = Color(hex: "#16161F")
    static let accent = Color(hex: "#8B5CF6")
    static let cyan = Color(hex: "#22D3EE")
    static let ok = Color(hex: "#22C55E")
    static let amber = Color(hex: "#F59E0B")
    static let danger = Color(hex: "#EF4444")
    static let pending = Color(hex: "#6B7280")
    static let crtGreen = Color(hex: "#33FF66")

    static let cardRadius: CGFloat = 20
    static let cardPadding: CGFloat = 16
    static let grid: CGFloat = 8

    static var spring: Animation { .spring(duration: 0.35, bounce: 0.2) }

    static func spring(reduceMotion: Bool) -> Animation {
        reduceMotion ? .easeInOut(duration: 0.2) : spring
    }
}

struct LuminaCardBackground: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        content
            .background {
                RoundedRectangle(cornerRadius: LuminaV2Theme.cardRadius, style: .continuous)
                    .fill(reduceTransparency
                          ? LuminaV2Theme.canvasElevated
                          : Color.white.opacity(0.06))
            }
            .overlay {
                RoundedRectangle(cornerRadius: LuminaV2Theme.cardRadius, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.08), lineWidth: 1)
            }
    }
}

private struct LuminaChromeGlassModifier: ViewModifier {
    var cornerRadius: CGFloat
    var interactive: Bool
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        if reduceTransparency {
            content.background(LuminaV2Theme.canvasElevated, in: shape)
        } else if #available(iOS 26.0, *) {
            content.glassEffect(.regular.interactive(interactive), in: shape)
        } else {
            content.background(.ultraThinMaterial, in: shape)
        }
    }
}

extension View {
    func luminaCard() -> some View {
        modifier(LuminaCardBackground())
    }

    func luminaChromeGlass(cornerRadius: CGFloat = 24, interactive: Bool = false) -> some View {
        modifier(LuminaChromeGlassModifier(cornerRadius: cornerRadius, interactive: interactive))
    }
}

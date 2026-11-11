import SwiftUI
import UIKit

enum T {
    /// Page fill. Matches iOS grouped lists (Settings / App Store).
    static let void = Color(.systemGroupedBackground)
    static let bg = void
    /// Inset tile fill. Content layer, never glass.
    static let panel = Color(.secondarySystemGroupedBackground)
    static let panelHi = Color(.tertiarySystemFill)
    static let stroke = Color.primary.opacity(0.10)
    /// Single accent for the one primary control on a screen. Status colors stay separate.
    static let accent = Color(red: 0.10, green: 0.48, blue: 1.0)
    /// Status ink. Call-site name `ember` stays so existing chrome compiles.
    static let ember = Color(red: 1.00, green: 0.45, blue: 0.28)
    static let emberSoft = Color(red: 1.00, green: 0.72, blue: 0.55)
    static let cyan = Color(red: 0.36, green: 0.68, blue: 1.00)
    static let good = Color(red: 0.20, green: 0.78, blue: 0.45)
    static let warn = Color(red: 1.00, green: 0.72, blue: 0.28)
    static let bad = Color(red: 1.00, green: 0.30, blue: 0.32)
    static let info = Color(red: 0.36, green: 0.68, blue: 1.00)
    static let violet = Color(red: 0.58, green: 0.42, blue: 0.98)

    static let mono = Font.system(size: 12, design: .monospaced)
    static let monoSm = Font.system(size: 11, design: .monospaced)
    static let monoLg = Font.system(size: 14, weight: .medium, design: .monospaced)
    static let title = Font.system(size: 28, weight: .bold)
    static let head = Font.system(size: 17, weight: .semibold)
    static let body = Font.system(size: 15, weight: .regular)
    static let tiny = Font.system(size: 12, weight: .medium)
}

struct Card<Content: View>: View {
    var padding: CGFloat = 16
    @ViewBuilder var content: () -> Content
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 22, style: .continuous)
        let strong = contrast == .increased || reduceTransparency
        content()
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(shape.fill(T.panel))
            .overlay(
                shape.strokeBorder(
                    Color.primary.opacity(strong ? 0.38 : 0.08),
                    lineWidth: strong ? 1.5 : 0.5)
            )
            .shadow(color: .black.opacity(0.16), radius: strong ? 0 : 12, y: strong ? 0 : 6)
    }
}

struct Pill: View {
    let text: String
    var color: Color = T.info

    var body: some View {
        Text(text)
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(color.opacity(0.14), in: Capsule())
    }
}

struct SectionLabel: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(.secondary)
    }
}

struct KeyValueRow: View {
    let key: String
    let value: String
    var mono: Bool = true
    var tint: Color? = nil

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(key)
                .font(T.body)
                .foregroundStyle(.secondary)
                .frame(width: 108, alignment: .leading)
            Text(value)
                .font(mono ? T.mono : T.body)
                .foregroundStyle(tint ?? Color.primary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 4)
        .frame(minHeight: 28)
    }
}

struct RunButton: View {
    let title: String
    var systemImage: String = "bolt.fill"
    var tint: Color = T.accent
    var disabled: Bool = false
    let action: () -> Void

    var body: some View {
        control
            .disabled(disabled)
            .opacity(disabled ? 0.5 : 1)
    }

    private var control: some View {
        let button = Button(action: {
            if !disabled {
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
            }
            action()
        }) {
            Label(title, systemImage: systemImage)
                .font(.system(size: 16, weight: .semibold))
                .frame(maxWidth: .infinity, minHeight: 44)
                .foregroundStyle(disabled ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.primary))
        }
        #if compiler(>=6.2)
        if #available(iOS 26.0, *) {
            return AnyView(button.buttonStyle(.glass).tint(disabled ? .gray : tint))
        }
        #endif
        return AnyView(
            button.luminaGlass(
                RoundedRectangle(cornerRadius: 22, style: .continuous),
                interactive: !disabled,
                tint: disabled ? nil : tint)
        )
    }
}

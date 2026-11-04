import SwiftUI
import UIKit

enum T {
    /// Solid sheet/splash fill. Tab screens use luminaCanvas() over LuminaBackdrop.
    static let void = Color(red: 0.035, green: 0.028, blue: 0.07)
    static let bg = void
    static let panel = Color(red: 0.11, green: 0.08, blue: 0.18).opacity(0.82)
    static let panelHi = Color(red: 0.18, green: 0.12, blue: 0.28)
    static let stroke = Color.white.opacity(0.12)
    /// Galaxy pink (call-site name `ember` kept so existing chrome compiles).
    static let ember = Color(red: 1.00, green: 0.38, blue: 0.72)
    static let emberSoft = Color(red: 1.00, green: 0.62, blue: 0.86)
    static let cyan = Color(red: 0.42, green: 0.72, blue: 1.00)
    static let good = Color(red: 0.42, green: 0.90, blue: 0.72)
    static let warn = Color(red: 1.00, green: 0.78, blue: 0.42)
    static let bad = Color(red: 1.00, green: 0.38, blue: 0.48)
    static let info = Color(red: 0.52, green: 0.70, blue: 1.00)
    static let violet = Color(red: 0.62, green: 0.42, blue: 1.00)

    static let mono = Font.system(size: 12, design: .monospaced)
    static let monoSm = Font.system(size: 10.5, design: .monospaced)
    static let monoLg = Font.system(size: 14, weight: .medium, design: .monospaced)
    static let title = Font.system(size: 26, weight: .bold, design: .rounded)
    static let head = Font.system(size: 15, weight: .semibold, design: .rounded)
    static let body = Font.system(size: 13, weight: .regular, design: .rounded)
    static let tiny = Font.system(size: 10.5, weight: .medium, design: .rounded)
}

struct Card<Content: View>: View {
    var padding: CGFloat = 14
    @ViewBuilder var content: () -> Content

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 16, style: .continuous)
        content()
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                ZStack {
                    shape.fill(T.panel)
                    shape.fill(
                        LinearGradient(colors: [T.ember.opacity(0.12), T.violet.opacity(0.10), T.cyan.opacity(0.06), .clear],
                                       startPoint: .topLeading, endPoint: .bottomTrailing)
                    )
                }
            }
            .overlay(
                shape.strokeBorder(
                    LinearGradient(colors: [T.ember.opacity(0.45), T.violet.opacity(0.28), Color.white.opacity(0.12), T.cyan.opacity(0.32)],
                                   startPoint: .topLeading, endPoint: .bottomTrailing),
                    lineWidth: 1)
            )
            .shadow(color: T.violet.opacity(0.14), radius: 12, y: 6)
    }
}

struct Pill: View {
    let text: String
    var color: Color = T.info

    var body: some View {
        Text(text)
            .font(T.tiny)
            .foregroundColor(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.14)))
            .overlay(Capsule().strokeBorder(color.opacity(0.35), lineWidth: 0.6))
    }
}

struct SectionLabel: View {
    let text: String

    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 10.5, weight: .bold, design: .rounded))
            .kerning(1.1)
            .foregroundColor(.white.opacity(0.34))
    }
}

struct KeyValueRow: View {
    let key: String
    let value: String
    var mono: Bool = true
    var tint: Color = .white.opacity(0.86)

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(key)
                .font(T.body)
                .foregroundColor(.white.opacity(0.42))
                .frame(width: 108, alignment: .leading)
            Text(value)
                .font(mono ? T.mono : T.body)
                .foregroundColor(tint)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 3)
    }
}

struct RunButton: View {
    let title: String
    var systemImage: String = "bolt.fill"
    var tint: Color = T.ember
    var disabled: Bool = false
    let action: () -> Void

    var body: some View {
        Button(action: {
            if !disabled {
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
            }
            action()
        }) {
            HStack(spacing: 7) {
                Image(systemName: systemImage).font(.system(size: 12, weight: .bold))
                Text(title).font(.system(size: 13, weight: .semibold, design: .rounded))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 11)
            .foregroundColor(disabled ? .white.opacity(0.28) : .white)
        }
        .luminaGlass(RoundedRectangle(cornerRadius: 12, style: .continuous),
                     interactive: !disabled, tint: disabled ? nil : tint)
        .disabled(disabled)
        .opacity(disabled ? 0.55 : 1)
    }
}

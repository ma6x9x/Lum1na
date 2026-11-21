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
    static let tabBarHeight: CGFloat = 64
    static let tabBarBottomInset: CGFloat = 12
    static let chipClearance: CGFloat = 88

    static var spring: Animation { .spring(duration: 0.35, bounce: 0.2) }

    static func spring(reduceMotion: Bool) -> Animation {
        reduceMotion ? .easeInOut(duration: 0.2) : spring
    }
}

/// Circuit-trace canvas reused from UI/CircuitBackgroundView (LabStage.idle).
struct LuminaV2CircuitCanvas: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    var body: some View {
        ZStack {
            LuminaV2Theme.canvas.ignoresSafeArea()
            if reduceTransparency {
                LuminaV2Theme.canvasElevated.ignoresSafeArea()
            } else if reduceMotion {
                CircuitBackgroundView(stage: .idle)
                    .opacity(0.55)
                    .allowsHitTesting(false)
            } else {
                CircuitBackgroundView(stage: .idle)
                    .opacity(0.7)
                    .allowsHitTesting(false)
            }
        }
        .ignoresSafeArea()
    }
}

struct LuminaCardBackground: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        content
            .background {
                let shape = RoundedRectangle(cornerRadius: LuminaV2Theme.cardRadius, style: .continuous)
                if reduceTransparency {
                    shape.fill(LuminaV2Theme.canvasElevated)
                } else {
                    #if compiler(>=6.2)
                    if #available(iOS 26.0, *) {
                        shape.fill(.clear)
                    } else {
                        ZStack {
                            shape.fill(.ultraThinMaterial)
                            shape.fill(Color.white.opacity(0.06))
                        }
                    }
                    #else
                    ZStack {
                        shape.fill(.ultraThinMaterial)
                        shape.fill(Color.white.opacity(0.06))
                    }
                    #endif
                }
            }
            .overlay {
                RoundedRectangle(cornerRadius: LuminaV2Theme.cardRadius, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.12), lineWidth: 1)
            }
            .modifier(LuminaCardGlassLift())
    }
}

private struct LuminaCardGlassLift: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        if reduceTransparency {
            content
        } else {
            #if compiler(>=6.2)
            if #available(iOS 26.0, *) {
                content.glassEffect(.regular, in: RoundedRectangle(cornerRadius: LuminaV2Theme.cardRadius, style: .continuous))
            } else {
                content
            }
            #else
            content
            #endif
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
                .overlay(shape.strokeBorder(Color.white.opacity(0.14), lineWidth: 1))
        } else {
            #if compiler(>=6.2)
            if #available(iOS 26.0, *) {
                if interactive {
                    content.glassEffect(.regular.interactive(), in: shape)
                } else {
                    content.glassEffect(.regular, in: shape)
                }
            } else {
                content
                    .background {
                        ZStack {
                            shape.fill(.ultraThinMaterial)
                            shape.fill(Color.white.opacity(0.08))
                        }
                    }
                    .overlay(shape.strokeBorder(Color.white.opacity(0.18), lineWidth: 1))
                    .shadow(color: .black.opacity(0.35), radius: 18, y: 8)
            }
            #else
            content
                .background {
                    ZStack {
                        shape.fill(.ultraThinMaterial)
                        shape.fill(Color.white.opacity(0.08))
                    }
                }
                .overlay(shape.strokeBorder(Color.white.opacity(0.18), lineWidth: 1))
                .shadow(color: .black.opacity(0.35), radius: 18, y: 8)
            #endif
        }
    }
}

private struct LuminaCapsuleGlassModifier: ViewModifier {
    var interactive: Bool
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        if reduceTransparency {
            content
                .background(LuminaV2Theme.canvasElevated, in: Capsule(style: .continuous))
                .overlay(Capsule(style: .continuous).strokeBorder(Color.white.opacity(0.14), lineWidth: 1))
        } else {
            #if compiler(>=6.2)
            if #available(iOS 26.0, *) {
                if interactive {
                    content.glassEffect(.regular.interactive(), in: Capsule(style: .continuous))
                } else {
                    content.glassEffect(.regular, in: Capsule(style: .continuous))
                }
            } else {
                content
                    .background {
                        ZStack {
                            Capsule(style: .continuous).fill(.ultraThinMaterial)
                            Capsule(style: .continuous).fill(Color.white.opacity(0.08))
                        }
                    }
                    .overlay(Capsule(style: .continuous).strokeBorder(Color.white.opacity(0.18), lineWidth: 1))
            }
            #else
            content
                .background {
                    ZStack {
                        Capsule(style: .continuous).fill(.ultraThinMaterial)
                        Capsule(style: .continuous).fill(Color.white.opacity(0.08))
                    }
                }
                .overlay(Capsule(style: .continuous).strokeBorder(Color.white.opacity(0.18), lineWidth: 1))
            #endif
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

    func luminaCapsuleGlass(interactive: Bool = true) -> some View {
        modifier(LuminaCapsuleGlassModifier(interactive: interactive))
    }
}

/// Floating ~64pt glass pill tab bar (selected = translucent wash, not solid fill).
struct LuminaFloatingTabBar: View {
    @Binding var selection: LuminaAppStore.LuminaTab
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var pressTrigger = 0

    private let tabs: [(LuminaAppStore.LuminaTab, String, String)] = [
        (.tests, "Tests", "list.bullet.rectangle"),
        (.chains, "Chains", "link"),
        (.console, "Console", "chevron.left.forwardslash.chevron.right"),
        (.tools, "Tools", "wrench.and.screwdriver"),
    ]

    var body: some View {
        HStack(spacing: 4) {
            ForEach(tabs, id: \.0) { tab, title, icon in
                let selected = selection == tab
                Button {
                    pressTrigger &+= 1
                    withAnimation(LuminaV2Theme.spring(reduceMotion: reduceMotion)) {
                        selection = tab
                    }
                } label: {
                    VStack(spacing: 4) {
                        Image(systemName: icon)
                            .font(.system(size: 18, weight: .semibold))
                        Text(title)
                            .font(.caption2.weight(.semibold))
                    }
                    .foregroundStyle(selected ? Color.white : Color.white.opacity(0.55))
                    .frame(maxWidth: .infinity)
                    .frame(height: 52)
                    .background {
                        if selected {
                            Capsule(style: .continuous)
                                .fill(selectedWash(for: tab))
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(PressableScaleButtonStyle(reduceMotion: reduceMotion))
                .sensoryFeedback(.selection, trigger: selection == tab ? pressTrigger : 0)
                .accessibilityLabel(title)
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .frame(height: LuminaV2Theme.tabBarHeight)
        .luminaChromeGlass(cornerRadius: 32, interactive: false)
        .padding(.horizontal, 18)
        .padding(.bottom, LuminaV2Theme.tabBarBottomInset)
    }

    private func selectedWash(for tab: LuminaAppStore.LuminaTab) -> Color {
        switch tab {
        case .console:
            return LuminaV2Theme.crtGreen.opacity(0.28)
        default:
            return LuminaV2Theme.accent.opacity(0.32)
        }
    }
}

/// Press scale 0.96–0.97; respects Reduce Motion.
struct PressableScaleButtonStyle: ButtonStyle {
    var reduceMotion: Bool
    var pressedScale: CGFloat = 0.96

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed && !reduceMotion ? pressedScale : 1)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

struct SharePayloadSheet: UIViewControllerRepresentable {
    let text: String

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [text], applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

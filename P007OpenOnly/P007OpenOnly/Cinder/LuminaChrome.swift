import SwiftUI
import UIKit
import Combine

// MARK: - Stamp
//
// Sideload check: Ident / KERNEL session banner must print this, or the
// phone still has an older IPA. Glass is chrome only — TAP bodies unchanged.

enum LuminaStamp {
    static let ui = "ios26-catalog-1"
}

final class LuminaTabs: ObservableObject {
    static let shared = LuminaTabs()
    @Published var index: Int = 0
}

// MARK: - Glass tier (liquid-glass-fallbacks-and-tiering)

enum GlassLevel: Int, Comparable {
    case opaque, material, refraction, native
    static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
}

private func resolveGlassLevel(reduceTransparency: Bool, constrained: Bool) -> GlassLevel {
    #if compiler(>=6.2)
    if #available(iOS 26.0, *), !reduceTransparency { return .native }
    #endif
    if reduceTransparency { return .opaque }
    if constrained { return .material }
    return .refraction
}

private func isPowerOrThermalConstrained() -> Bool {
    let info = ProcessInfo.processInfo
    return info.isLowPowerModeEnabled
        || info.thermalState == .serious
        || info.thermalState == .critical
}

private struct GlassLevelKey: EnvironmentKey {
    static let defaultValue: GlassLevel = .material
}

extension EnvironmentValues {
    var glassLevel: GlassLevel {
        get { self[GlassLevelKey.self] }
        set { self[GlassLevelKey.self] = newValue }
    }
}

struct GlassTierRoot<Content: View>: View {
    @ViewBuilder var content: Content
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @State private var constrained = isPowerOrThermalConstrained()

    var body: some View {
        content
            .environment(\.glassLevel,
                         resolveGlassLevel(reduceTransparency: reduceTransparency,
                                           constrained: constrained))
            .onReceive(NotificationCenter.default.publisher(for: .NSProcessInfoPowerStateDidChange)
                .receive(on: RunLoop.main)) { _ in
                constrained = isPowerOrThermalConstrained()
            }
            .onReceive(NotificationCenter.default.publisher(for: ProcessInfo.thermalStateDidChangeNotification)
                .receive(on: RunLoop.main)) { _ in
                constrained = isPowerOrThermalConstrained()
            }
    }
}

// MARK: - Adaptive glass (controls only — never on list cards)

private struct LuminaGlassMod<S: InsettableShape>: ViewModifier {
    var shape: S
    var interactive: Bool
    var tint: Color?
    @Environment(\.glassLevel) private var level
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        let contrast = UIAccessibility.isDarkerSystemColorsEnabled
        if reduceTransparency || level == .opaque {
            content
                .background(shape.fill(T.panelHi))
                .overlay(shape.strokeBorder(Color.white.opacity(contrast ? 0.45 : 0.22), lineWidth: contrast ? 1.4 : 0.7))
        } else {
            #if compiler(>=6.2)
            if #available(iOS 26.0, *), level == .native {
                native(content)
            } else {
                fallback(content, contrast: contrast)
            }
            #else
            fallback(content, contrast: contrast)
            #endif
        }
    }

    #if compiler(>=6.2)
    @available(iOS 26.0, *)
    @ViewBuilder
    private func native(_ content: Content) -> some View {
        let glass: Glass = {
            var g = Glass.regular
            if let tint { g = g.tint(tint) }
            if interactive { g = g.interactive() }
            return g
        }()
        content.glassEffect(glass, in: shape)
    }
    #endif

    private func fallback(_ content: Content, contrast: Bool) -> some View {
        content
            .background {
                ZStack {
                    shape.fill(.ultraThinMaterial)
                    if let tint {
                        shape.fill(tint.opacity(0.18))
                    } else {
                        shape.fill(Color.white.opacity(0.06))
                    }
                    shape.fill(
                        LinearGradient(colors: [Color.white.opacity(0.28), .clear],
                                       startPoint: .top,
                                       endPoint: UnitPoint(x: 0.5, y: 0.42))
                    )
                }
            }
            .overlay(
                shape.strokeBorder(
                    AngularGradient(stops: [
                        .init(color: .white.opacity(0.70), location: 0.00),
                        .init(color: .white.opacity(0.10), location: 0.22),
                        .init(color: .clear, location: 0.46),
                        .init(color: .white.opacity(0.22), location: 0.58),
                        .init(color: .clear, location: 0.76),
                        .init(color: .white.opacity(0.65), location: 1.00)
                    ], center: .center, angle: .degrees(-135)),
                    lineWidth: contrast ? 1.5 : 0.8)
                .blendMode(.plusLighter)
            )
            .shadow(color: .black.opacity(0.28), radius: 16, y: 8)
    }
}

extension View {
    func luminaGlass<S: InsettableShape>(_ shape: S, interactive: Bool = false, tint: Color? = nil) -> some View {
        modifier(LuminaGlassMod(shape: shape, interactive: interactive, tint: tint))
    }

    /// Opaque grouped page. Lists and tool panes sit on this so text stays legible.
    func luminaCanvas() -> some View {
        background { Color(.systemGroupedBackground).ignoresSafeArea() }
    }
}

// MARK: - Backdrop (colorful so glass has something to refract)

struct LuminaBackdrop: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.glassLevel) private var level
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    var body: some View {
        let paused = reduceMotion || reduceTransparency || level == .opaque
            || ProcessInfo.processInfo.isLowPowerModeEnabled
        TimelineView(.animation(minimumInterval: paused ? 120 : (1.0 / 20.0), paused: paused)) { context in
            let t = paused ? 0 : context.date.timeIntervalSinceReferenceDate
            ZStack {
                Color(red: 0.05, green: 0.07, blue: 0.12).ignoresSafeArea()
                mesh(t)
                orbs(t)
                grain
            }
        }
        .ignoresSafeArea()
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    @ViewBuilder
    private func mesh(_ t: TimeInterval) -> some View {
        if #available(iOS 18.0, *) {
            let wobble = Float(0.04 * sin(t * 0.18))
            MeshGradient(
                width: 3, height: 3,
                points: [
                    SIMD2<Float>(0, 0), SIMD2<Float>(0.5, 0), SIMD2<Float>(1, 0),
                    SIMD2<Float>(0, 0.52), SIMD2<Float>(0.50 + wobble, 0.42), SIMD2<Float>(1, 0.48),
                    SIMD2<Float>(0, 1), SIMD2<Float>(0.5, 1), SIMD2<Float>(1, 1)
                ],
                colors: [
                    Color(red: 0.10, green: 0.22, blue: 0.42),
                    Color(red: 0.18, green: 0.40, blue: 0.62),
                    Color(red: 0.08, green: 0.16, blue: 0.30),
                    Color(red: 0.16, green: 0.28, blue: 0.40),
                    Color(red: 0.22, green: 0.24, blue: 0.32),
                    Color(red: 0.42, green: 0.32, blue: 0.20),
                    Color(red: 0.10, green: 0.14, blue: 0.22),
                    Color(red: 0.55, green: 0.40, blue: 0.22),
                    Color(red: 0.16, green: 0.18, blue: 0.16)
                ]
            )
            .ignoresSafeArea()
            .opacity(0.92)
        } else {
            LinearGradient(
                colors: [
                    Color(red: 0.16, green: 0.32, blue: 0.52),
                    Color(red: 0.10, green: 0.16, blue: 0.28),
                    Color(red: 0.36, green: 0.26, blue: 0.14)
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()
        }
    }

    private func orbs(_ t: TimeInterval) -> some View {
        GeometryReader { geo in
            let w = geo.size.width
            let h = geo.size.height
            ZStack {
                Circle()
                    .fill(Color(red: 0.35, green: 0.62, blue: 0.90).opacity(0.28))
                    .frame(width: 240, height: 240)
                    .blur(radius: 70)
                    .offset(x: w * 0.18 + CGFloat(12 * sin(t * 0.21)),
                            y: -h * 0.22 + CGFloat(10 * cos(t * 0.17)))
                Circle()
                    .fill(Color(red: 0.90, green: 0.62, blue: 0.28).opacity(0.22))
                    .frame(width: 260, height: 260)
                    .blur(radius: 80)
                    .offset(x: -w * 0.10 + CGFloat(9 * cos(t * 0.16)),
                            y: h * 0.28 + CGFloat(11 * sin(t * 0.13)))
                Circle()
                    .fill(Color(red: 0.45, green: 0.55, blue: 0.72).opacity(0.18))
                    .frame(width: 200, height: 200)
                    .blur(radius: 74)
                    .offset(x: w * 0.30 + CGFloat(10 * cos(t * 0.14)),
                            y: h * 0.05 + CGFloat(8 * sin(t * 0.19)))
            }
        }
        .ignoresSafeArea()
    }

    private var grain: some View {
        Image(uiImage: LuminaNoise.image)
            .resizable(resizingMode: .tile)
            .opacity(0.045)
            .blendMode(.overlay)
            .ignoresSafeArea()
    }
}

enum LuminaNoise {
    static let image: UIImage = {
        let size = CGSize(width: 96, height: 96)
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        return UIGraphicsImageRenderer(size: size, format: format).image { ctx in
            var rng = SystemRandomNumberGenerator()
            for y in 0..<Int(size.height) {
                for x in 0..<Int(size.width) {
                    let v = CGFloat(UInt8.random(in: 0...255, using: &rng)) / 255
                    UIColor(white: v, alpha: 1).setFill()
                    ctx.fill(CGRect(x: x, y: y, width: 1, height: 1))
                }
            }
        }
    }()
}

struct LuminaMark: View {
    var size: CGFloat = 72

    var body: some View {
        ZStack {
            Circle()
                .fill(T.accent.opacity(0.22))
                .frame(width: size, height: size)
            Circle()
                .fill(.ultraThinMaterial)
                .frame(width: size * 0.72, height: size * 0.72)
            Image(systemName: "circle.hexagongrid.fill")
                .font(.system(size: size * 0.28, weight: .semibold))
                .foregroundStyle(T.accent)
                .accessibilityHidden(true)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Lum1na")
    }
}

// MARK: - Copy bus + toast

final class LuminaCopyBus: ObservableObject {
    static let shared = LuminaCopyBus()
    @Published var message: String?
    private var token = UUID()

    func copy(_ text: String, label: String = "Copied") {
        UIPasteboard.general.string = text
        UIImpactFeedbackGenerator(style: .soft).impactOccurred()
        let id = UUID()
        token = id
        withAnimation(.snappy) { message = label }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.45) {
            if self.token == id {
                withAnimation(.snappy) { self.message = nil }
            }
        }
    }
}

struct CopyToastOverlay: View {
    @ObservedObject private var bus = LuminaCopyBus.shared

    var body: some View {
        if let message = bus.message {
            HStack(spacing: 8) {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(T.good)
                Text(message)
                    .font(T.tiny)
                    .foregroundStyle(.primary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .luminaGlass(Capsule(), interactive: false)
            .padding(.bottom, 8)
            .transition(.move(edge: .bottom).combined(with: .opacity))
            .accessibilityAddTraits(.updatesFrequently)
        }
    }
}

// MARK: - Board snapshot + Next TAP (read-only; never auto-fires)

struct BoardSnapshot {
    var sku: String
    var skuEnum: LabSku
    var osversion: String
    var hasKread: Bool
    var conversion: Bool
    var occupancy: Bool
    var leakCount: Int
    var kreadSignal: String
    var lastTap: String
    var nextID: String
    var nextWhy: String

    static func current() -> BoardSnapshot {
        let b = P007Board.shared()
        let sku = LabDeviceProfile.sku()
        let occ: Bool = {
            let row = LabLearn.row()
            if let s = row["occupancy"] as? String { return s == "YES" }
            return false
        }()
        let conv = LabLearn.conversionConfirmed()
        let last = Self.readLastTap()
        let leaks = b.leaks
        let next = Self.nextTap(sku: sku, hasKread: b.hasKread, conversion: conv,
                                occupancy: occ, leakCount: leaks.count, lastTap: last)
        return BoardSnapshot(
            sku: LabDeviceProfile.skuName(),
            skuEnum: sku,
            osversion: LabDeviceProfile.osversion(),
            hasKread: b.hasKread,
            conversion: conv,
            occupancy: occ,
            leakCount: leaks.count,
            kreadSignal: b.kreadSignal,
            lastTap: last,
            nextID: next.0,
            nextWhy: next.1
        )
    }

    static func readLastTap() -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        guard let url = docs?.appendingPathComponent("p007_last_tap.txt") else { return "" }
        return (try? String(contentsOf: url, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    /// Honest SKU door. Suggestion only — isolation still one TAP per force-quit.
    static func nextTap(sku: LabSku, hasKread: Bool, conversion: Bool,
                        occupancy: Bool, leakCount: Int, lastTap: String) -> (String, String) {
        if hasKread {
            return ("board", "hasKread live. AfterKread HOLD. Copy board JSON.")
        }
        switch sku {
        case LabSkuA14_23F77:
            if lastTap.isEmpty {
                return ("ident", "Ident first. One TAP per force-quit.")
            }
            if leakCount == 0 && lastTap != "krw" && lastTap != "p139"
                && lastTap != "p010qleak" && lastTap != "p063" {
                return ("krw", "KERNEL: P139 disclose then P044 N=192. Skip P099/P073.")
            }
            if !occupancy {
                return ("krw", "KERNEL smash P044 N=192 into LIVE 0x820. Occupancy is not kread.")
            }
            return ("kreadtest", "Occupancy/conversion ≠ hasKread. kread32(kbase)==0xfeedfacf.")
        case LabSkuA12X_23H30, LabSkuA12X_other:
            if lastTap.isEmpty { return ("ident", "Ident FIELD# 0x408 / +0x550. No 23G71 VA paste.") }
            if lastTap == "ident" { return ("krw", "KERNEL harvest-only. Skip P044 / 254.") }
            if lastTap == "krw" || lastTap == "p139" { return ("p010qleak", "P010 disclose. FIELD# word1=+0x550.") }
            if lastTap == "p010qleak" { return ("p063", "P063 aio kptr. Then kern.decmpfs if still no kptrs.") }
            if lastTap == "p063" { return ("p126", "kern.decmpfs leak. Skip Facet A remaining-fire.") }
            return ("kreadtest", "A12X PPL AfterKread is HOLD until kread32. Facet A EXPECT-BAD.")
        case LabSkuA12X_23G71:
            if lastTap.isEmpty { return ("ident", "Ident 23G71. 43748 patched 26.6.") }
            return ("krw", "Harvest P139. Skip P044 remaining-fire. 43748 patched.")
        case LabSkuT8150_24A435, LabSkuT8150_other:
            if lastTap.isEmpty { return ("ident", "Ident T8150. One TAP per force-quit.") }
            if lastTap == "ident" { return ("krw", "KERNEL: P139 + P114 then P149 isolate.") }
            if lastTap == "krw" || lastTap == "p139" { return ("p149", "P149 isolate. PIPE-HIT is not hasKread. Reboot after.") }
            return ("kreadtest", "kread32(kbase)==0xfeedfacf. SPTM HOLD.")
        case LabSkuA14_21D50:
            return ("ident", "12 mini 21D50: twin CLASS/FIELD only. 43748 absent.")
        default:
            return ("ident", "Unknown SKU. Ident + prove matrix first.")
        }
    }

    var copyBlock: String {
        """
        ui=\(LuminaStamp.ui)
        sku=\(sku) osversion=\(osversion)
        hasKread=\(hasKread ? "YES" : "NO") occupancy=\(occupancy ? "YES" : "NO") conversion=\(conversion ? "YES" : "NO")
        leaks=\(leakCount) last=\(lastTap.isEmpty ? "—" : lastTap)
        \(kreadSignal)
        NEXT \(nextID) — \(nextWhy)
        Isolation: one TAP per force-quit. Suggestion does not fire.
        """
    }
}

struct BoardHUD: View {
    @Binding var tab: Int
    @EnvironmentObject private var engine: LabEngine
    @State private var snap = BoardSnapshot.current()

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                hudChip(snap.sku, color: T.accent)
                hudChip(snap.hasKread ? "kread YES" : "kread NO",
                        color: snap.hasKread ? T.good : T.bad)
                hudChip(snap.conversion ? "conv YES" : "conv NO",
                        color: snap.conversion ? T.warn : Color.secondary)
                hudChip(snap.occupancy ? "occ YES" : "occ NO",
                        color: snap.occupancy ? T.ember : Color.secondary)
                Spacer(minLength: 0)
                Text(LuminaStamp.ui)
                    .font(T.monoSm)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }
            Button {
                LuminaCopyBus.shared.copy(snap.copyBlock, label: "Next TAP · \(snap.nextID)")
                reveal(snap.nextID)
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "arrow.right.circle.fill")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(T.accent)
                    Text("NEXT \(snap.nextID)")
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.primary)
                    Text(snap.nextWhy)
                        .font(T.tiny)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    Spacer(minLength: 0)
                }
                .frame(minHeight: 32)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Copy next tap \(snap.nextID)")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .luminaGlass(RoundedRectangle(cornerRadius: 22, style: .continuous), interactive: true)
        .padding(.horizontal, 12)
        .padding(.top, 2)
        .onAppear { snap = BoardSnapshot.current() }
        .onChange(of: engine.logLines.count) { _, _ in snap = BoardSnapshot.current() }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.willEnterForegroundNotification)) { _ in
            snap = BoardSnapshot.current()
        }
    }

    private func hudChip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 10, weight: .semibold, design: .monospaced))
            .foregroundColor(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.14)))
            .overlay(Capsule().strokeBorder(color.opacity(0.40), lineWidth: 0.6))
            .lineLimit(1)
            .minimumScaleFactor(0.7)
    }

    private func reveal(_ id: String) {
        let console = Set(["ident", "krw", "pathtest", "kreadtest", "p044", "p139",
                           "p010qleak", "p063", "p149", "p114", "board", "cs2", "p100"])
        LuminaTabs.shared.index = console.contains(id) ? 4 : 1
    }
}

struct SKUDoorCard: View {
    @EnvironmentObject private var engine: LabEngine
    private var snap: BoardSnapshot {
        _ = engine.logLines.count
        return BoardSnapshot.current()
    }

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SectionLabel(text: "SKU door")
                    Spacer()
                    Pill(text: LuminaStamp.ui, color: T.cyan)
                }
                Text(snap.nextWhy)
                    .font(T.body)
                    .foregroundColor(.white.opacity(0.86))
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Pill(text: "NEXT \(snap.nextID)", color: T.ember)
                    if !snap.lastTap.isEmpty {
                        Pill(text: "last \(snap.lastTap)", color: T.info)
                    }
                    Pill(text: "\(snap.leakCount) leaks", color: snap.leakCount > 0 ? T.good : T.warn)
                }
                Text("Tap NEXT on the HUD to copy. It never auto-fires. One TAP per force-quit.")
                    .font(T.tiny)
                    .foregroundColor(.white.opacity(0.38))
            }
        }
    }
}

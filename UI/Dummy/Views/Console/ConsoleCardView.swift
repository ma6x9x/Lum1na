import SwiftUI

/// Compact home-board console: a glass CRT showing the latest lines,
/// bottom-anchored. The expand control opens the fullscreen log panel.
struct ConsoleCardView: View {
    var onExpand: () -> Void

    @Environment(LuminaRunModel.self) private var model
    @Environment(AppSettings.self) private var settings

    var body: some View {
        CRTTerminalView(style: settings.consoleStyle) {
            VStack(alignment: .leading, spacing: 4) {
                header
                ViewThatFits(in: .vertical) {
                    ConsoleLogView(compact: true)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxHeight: .infinity, alignment: .top)
                    ConsoleLogView(compact: true)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(height: logHeight, alignment: .bottom)
                        .clipped()
                }
                .frame(height: logHeight)
                .overlay {
                    PixelConfettiView(successDate: model.successDate)
                        .allowsHitTesting(false)
                }
            }
            .padding(.horizontal, 11)
            .padding(.top, 6)
            .padding(.bottom, 8)
        }
    }

    private var header: some View {
        HStack(spacing: 8) {
            Text("CONSOLE")
                .tracking(1.5)
                .foregroundStyle(Palette.phosphorViolet)
            Spacer()
            Text(statusLabel)
                .tracking(1.5)
                .foregroundStyle(model.phase == .idle ? Palette.phosphorViolet : Palette.success)
                .contentTransition(.opacity)
            Button(action: onExpand) {
                Image(systemName: "arrow.up.left.and.arrow.down.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Palette.phosphorViolet)
                    .frame(width: 44, height: 32)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Expand console")
        }
        .font(TerminalFont.font(settings.consoleStyle, size: 15, relativeTo: .caption))
        .dynamicTypeSize(...DynamicTypeSize.xxxLarge)
    }

    private let logHeight: CGFloat = 146

    private var statusLabel: String {
        switch model.phase {
        case .idle: "READY"
        case .running: "● LIVE"
        case .success: "DONE"
        case .cancelled: "HALTED"
        }
    }
}

#Preview("Console – Dark") {
    let model = LuminaRunModel()
    return ConsoleCardView(onExpand: {})
        .environment(model)
        .environment(AppSettings())
        .environment(\.luminaMotion, MotionLevel.full)
        .padding()
        .background(.black)
        .preferredColorScheme(.dark)
        .task { model.illuminate() }
}

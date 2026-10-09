import SwiftUI

/// The live console card: a CRT terminal (or clean log) showing the latest
/// entries bottom-anchored, with a status readout and an expand button.
struct ConsoleCardView: View {
    var onExpand: () -> Void

    @Environment(LuminaRunModel.self) private var model
    @Environment(AppSettings.self) private var settings

    var body: some View {
        CRTTerminalView(style: settings.consoleStyle) {
            VStack(alignment: .leading, spacing: 4) {
                header
                // Top-aligned while it fits, bottom-anchored (newest visible) once it overflows.
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
                .foregroundStyle(Palette.phosphorViolet)
            Spacer()
            Text(statusLabel)
                .foregroundStyle(model.phase == .idle ? Palette.phosphorViolet : Palette.success)
                .contentTransition(.opacity)
            Button("Open full console", systemImage: "arrow.up.left.and.arrow.down.right", action: onExpand)
                .labelStyle(.iconOnly)
                .font(.caption)
                .foregroundStyle(Palette.phosphorViolet)
                .frame(width: 44, height: 28, alignment: .trailing)
                .contentShape(.rect)
        }
        .font(TerminalFont.font(settings.consoleStyle, size: 15, relativeTo: .caption))
        .tracking(1.5)
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

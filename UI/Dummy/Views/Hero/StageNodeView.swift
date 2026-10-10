import SwiftUI

/// A stage as a coloured glass pad on the board (cpu / bandage / lock.shield /
/// gearshape.2). Glows in its colour while active, stays lit with a check
/// badge once done. The glass itself comes from `glassSurface` (stock
/// `glassEffect`, opaque under Reduce Transparency).
struct StageNodeView: View {
    let stage: RunStage
    let status: StageStatus
    var size: CGFloat = 58
    var labelBelow: Bool
    var pulse: Double = 0

    private var lit: Bool { status != .pending }
    private var shape: RoundedRectangle { RoundedRectangle(cornerRadius: size * 0.29, style: .continuous) }

    var body: some View {
        ZStack {
            Image(systemName: stage.symbol)
                .font(.system(size: size * 0.42, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(lit ? .white : stage.color)
                .shadow(color: lit ? stage.color : .clear, radius: 4)
                .symbolEffect(.bounce, value: status == .done)
                .frame(width: size, height: size)
                .background {
                    shape.fill(LinearGradient(
                        colors: [stage.color.opacity(fillTop), stage.color.opacity(lit ? 0.14 : 0.05)],
                        startPoint: .topLeading, endPoint: .bottomTrailing
                    ))
                }
                .glassSurface(shape, tint: lit ? stage.color.opacity(0.35) : nil)
                .overlay { shape.strokeBorder(stage.color.opacity(lit ? 0.85 : 0.4), lineWidth: 1) }
                .shadow(color: stage.color.opacity(glow), radius: 10 + 8 * pulse)
            if status == .done {
                checkBadge
                    .offset(x: size / 2 - 2, y: -size / 2 + 2)
                    .transition(.scale.combined(with: .opacity))
            }
        }
        .overlay(alignment: labelBelow ? .bottom : .top) {
            Text(stage.title.uppercased())
                .font(.caption2.weight(.semibold))
                .tracking(1.4)
                .padding(.trailing, -1.4)
                .foregroundStyle(.secondary)
                .fixedSize()
                .offset(y: labelBelow ? 18 : -18)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Stage \(stage.number), \(stage.title)")
        .accessibilityValue(statusDescription)
    }

    private var fillTop: Double {
        switch status {
        case .pending: 0.16
        case .active: 0.30 + 0.15 * pulse
        case .done: 0.42
        }
    }

    private var glow: Double {
        switch status {
        case .pending: 0
        case .active: 0.5 + 0.4 * pulse
        case .done: 0.65
        }
    }

    private var checkBadge: some View {
        Image(systemName: "checkmark")
            .font(.system(size: 10, weight: .black))
            .foregroundStyle(Color(red: 0.02, green: 0.08, blue: 0.04))
            .frame(width: 19, height: 19)
            .background(Palette.success, in: .circle)
            .overlay { Circle().strokeBorder(.white.opacity(0.7), lineWidth: 1.5) }
            .shadow(color: Palette.success.opacity(0.8), radius: 5)
    }

    private var statusDescription: String {
        switch status {
        case .pending: "Pending"
        case .active: "In progress"
        case .done: "Complete"
        }
    }
}

#Preview("Nodes") {
    HStack(spacing: 30) {
        StageNodeView(stage: .kernel, status: .done, labelBelow: true)
        StageNodeView(stage: .patchset, status: .active, labelBelow: true, pulse: 0.6)
        StageNodeView(stage: .sandbox, status: .pending, labelBelow: true)
    }
    .padding(40)
    .background(Color(red: 0.02, green: 0.024, blue: 0.06))
    .preferredColorScheme(.dark)
}

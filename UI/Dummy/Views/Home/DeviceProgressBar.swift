import SwiftUI

/// Bottom strip: hex device mark, machine + iOS, thin progress line,
/// and the stage readout. A check means kread is proven.
struct DeviceProgressBar: View {
    @Environment(LuminaRunModel.self) private var model
    @ObservedObject private var exploits = ExploitManager.shared

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            deviceMark
            VStack(alignment: .leading, spacing: 6) {
                Text(DeviceUtils.currentDeviceIdentifier)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.white)
                Text("iOS \(DeviceUtils.marketingVersion)")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.white.opacity(0.55))
                progressLine
            }
            Spacer(minLength: 8)
            stageReadout
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(DeviceUtils.currentDeviceIdentifier), iOS \(DeviceUtils.marketingVersion), \(stageTitle) \(statusWord)")
    }

    private var deviceMark: some View {
        ZStack {
            DeviceHexagon()
                .stroke(Palette.violet.opacity(0.9), lineWidth: 1.4)
                .frame(width: 36, height: 40)
                .shadow(color: Palette.violet.opacity(0.6), radius: 4)
            Image(systemName: "iphone")
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(Palette.violet)
        }
        .accessibilityHidden(true)
    }

    private var progressLine: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(.white.opacity(0.18))
                Capsule()
                    .fill(.white)
                    .frame(width: max(0, proxy.size.width * fill))
            }
        }
        .frame(height: 3)
        .accessibilityHidden(true)
    }

    private var stageReadout: some View {
        HStack(spacing: 8) {
            VStack(alignment: .trailing, spacing: 1) {
                Text(stageTitle)
                    .font(.system(size: 11, weight: .semibold))
                    .tracking(0.6)
                Text(statusWord)
                    .font(.system(size: 11, weight: .medium))
                    .tracking(0.8)
            }
            .foregroundStyle(.white.opacity(0.85))
            if model.isFinished {
                Image(systemName: "checkmark")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(width: 26, height: 26)
                    .background(Circle().stroke(.white.opacity(0.85), lineWidth: 1.4))
            }
        }
    }

    private var fill: Double {
        if model.isFinished { return 1 }
        return min(max(exploits.progress, 0), 1)
    }

    private var stageNumber: Int {
        if model.isFinished { return 4 }
        if exploits.progress <= 0 { return 0 }
        return min(4, max(1, Int((exploits.progress * 4).rounded(.up))))
    }

    private var stageTitle: String { "STAGE \(stageNumber) / 4" }

    private var statusWord: String {
        if model.isFinished { return "COMPLETE" }
        if exploits.isRunning { return "RUNNING" }
        if exploits.progress >= 1 { return "HOLD" }
        return "READY"
    }
}

private struct DeviceHexagon: Shape {
    func path(in rect: CGRect) -> Path {
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let radius = min(rect.width, rect.height) / 2
        var path = Path()
        for index in 0..<6 {
            let angle = CGFloat(index) * .pi / 3 - .pi / 2
            let point = CGPoint(
                x: center.x + radius * cos(angle),
                y: center.y + radius * sin(angle)
            )
            if index == 0 { path.move(to: point) } else { path.addLine(to: point) }
        }
        path.closeSubpath()
        return path
    }
}

#Preview("Device bar") {
    DeviceProgressBar()
        .environment(LuminaRunModel())
        .padding()
        .background(.black)
        .preferredColorScheme(.dark)
}

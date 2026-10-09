import SwiftUI

/// The device chip ("iPhone 12 · 26.5") and the live status chip with a
/// coloured dot. Both are glass pills.
struct StatusChipsView: View {
    @Environment(AppSettings.self) private var settings
    @Environment(LuminaRunModel.self) private var model

    var body: some View {
        HStack(spacing: 10) {
            deviceChip
            statusChip
            Spacer(minLength: 0)
        }
    }

    private var shortVersion: String {
        settings.systemVersion.replacingOccurrences(of: "iOS ", with: "")
    }

    private var deviceChip: some View {
        Text("\(settings.deviceName) · \(shortVersion)")
            .font(.footnote.weight(.medium))
            .foregroundStyle(.primary)
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .glassSurface(Capsule())
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Device \(settings.deviceName), system \(settings.systemVersion)")
    }

    private var statusChip: some View {
        HStack(spacing: 7) {
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
                .shadow(color: statusColor.opacity(0.8), radius: 4)
            Text(model.statusText)
                .font(.footnote.weight(.semibold))
                .contentTransition(.interpolate)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .glassSurface(Capsule(), tint: statusColor.opacity(0.35))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Status \(model.statusText)")
    }

    private var statusColor: Color {
        switch model.phase {
        case .idle: Color(red: 0.30, green: 0.85, blue: 0.55)
        case .running: Palette.cyan
        case .success: Palette.violet
        case .cancelled: Color(red: 1.0, green: 0.75, blue: 0.3)
        }
    }
}

#Preview("Chips – Dark") {
    StatusChipsView()
        .environment(AppSettings())
        .environment(LuminaRunModel())
        .padding()
        .background(.black)
        .preferredColorScheme(.dark)
}

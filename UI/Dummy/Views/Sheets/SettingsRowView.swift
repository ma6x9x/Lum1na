import SwiftUI

/// A single settings row: a title on the left and arbitrary trailing content
/// (static value or a menu). Rendered as a subtle tile, not a glass layer, since
/// it already sits inside the glass settings card.
struct SettingsRowView<Trailing: View>: View {
    var title: String
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack {
            Text(title)
                .font(.body)
                .foregroundStyle(.primary)
            Spacer(minLength: 12)
            trailing
                .font(.body)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 16)
        .frame(minHeight: 52)
        .background(.white.opacity(0.08), in: .rect(cornerRadius: 14, style: .continuous))
    }
}

#Preview("Settings row") {
    VStack {
        SettingsRowView(title: "Device") {
            Text("iPhone 12")
        }
        SettingsRowView(title: "Appearance") {
            Label("Dark", systemImage: "chevron.up.chevron.down").labelStyle(.titleAndIcon)
        }
    }
    .padding()
    .background(.black)
    .preferredColorScheme(.dark)
}

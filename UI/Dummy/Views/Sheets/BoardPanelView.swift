import SwiftUI

/// The one panel host for the home board: settings, catalog and lab all render
/// as a centered card over the live circuit background. The hero and console
/// hide while a panel is up; the board and the LUM1NA header (with its Done
/// button) stay. Dismissal goes through the header, so there is no second Done.
/// The card hugs its content, centers vertically, and only grows to the
/// available height (scrolling internally) when the content is taller.
struct BoardPanelView<Content: View>: View {
    var title: String
    @ViewBuilder var content: Content

    @State private var contentHeight: CGFloat = 0

    var body: some View {
        GeometryReader { geo in
            card(available: geo.size.height)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func card(available: CGFloat) -> some View {
        let chrome: CGFloat = 78 // title row + outer paddings
        let cap = contentHeight > 0 ? min(contentHeight + chrome, available) : available
        return VStack(spacing: 0) {
            Text(title)
                .font(.title3.weight(.semibold))
                .foregroundStyle(.primary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                .padding(.bottom, 4)

            ScrollView {
                content
                    .onGeometryChange(for: CGFloat.self) { proxy in
                        proxy.size.height
                    } action: { height in
                        contentHeight = height
                    }
            }
            .scrollBounceBehavior(.basedOnSize)
        }
        .padding(14)
        .glassSurface(RoundedRectangle(cornerRadius: 28, style: .continuous))
        .frame(maxHeight: cap)
    }
}

#Preview("Board panel") {
    BoardPanelView(title: "Settings") {
        SettingsRowView(title: "Device") { Text("iPhone") }
    }
    .frame(maxWidth: 560)
    .padding(18)
    .background(Color(red: 0.02, green: 0.024, blue: 0.06))
    .preferredColorScheme(.dark)
}

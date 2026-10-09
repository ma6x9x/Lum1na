import SwiftUI

/// Renders the "Lum1na" wordmark with a gradient-highlighted numeral "1".
///
/// The full brand name is exposed to VoiceOver as a single accessible label.
struct WordmarkView: View {
    var size: CGFloat = 40

    var body: some View {
        let lum = Text("Lum")
        let one = Text("1").foregroundStyle(Palette.wordmarkGradient)
        let na = Text("na")

        Text("\(lum)\(one)\(na)")
            .font(.system(size: size, weight: .bold, design: .rounded))
            .foregroundStyle(.primary)
            .kerning(0.5)
            .accessibilityLabel("Lum1na")
            .accessibilityAddTraits(.isHeader)
    }
}

#Preview("Wordmark – Dark") {
    WordmarkView()
        .padding()
        .background(.black)
        .preferredColorScheme(.dark)
}

#Preview("Wordmark – Light") {
    WordmarkView()
        .padding()
        .preferredColorScheme(.light)
}

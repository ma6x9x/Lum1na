import SwiftUI

struct Lum1naLogo: View {
    var size: CGFloat = 180

    var body: some View {
        ZStack {
            Circle()
                .fill(
                    RadialGradient(
                        colors: [
                            Color.white.opacity(0.95),
                            Color.cyan.opacity(0.9),
                            Color.purple.opacity(0.9),
                            Color.clear
                        ],
                        center: .center,
                        startRadius: 2,
                        endRadius: size * 0.62
                    )
                )
                .blur(radius: size * 0.07)

            Circle()
                .stroke(
                    AngularGradient(
                        colors: [.purple, .blue, .cyan, .purple],
                        center: .center
                    ),
                    lineWidth: size * 0.08
                )
                .shadow(color: .purple.opacity(0.8), radius: size * 0.12)

            Image(systemName: "sparkle")
                .font(.system(size: size * 0.42, weight: .regular))
                .foregroundStyle(
                    LinearGradient(
                        colors: [.white, .pink.opacity(0.95), .cyan],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .shadow(color: .white.opacity(0.85), radius: size * 0.08)
        }
        .frame(width: size, height: size)
        .accessibilityLabel("Lum1na logo")
    }
}

#Preview {
    ZStack {
        Color(red: 0.02, green: 0.01, blue: 0.12).ignoresSafeArea()
        Lum1naLogo()
    }
}

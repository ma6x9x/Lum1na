import SwiftUI

struct ContentView: View {
    var body: some View {
        NavigationStack {
            ZStack {
                LinearGradient(
                    colors: [
                        Color(red: 0.02, green: 0.01, blue: 0.12),
                        Color(red: 0.08, green: 0.02, blue: 0.20),
                        Color(red: 0.01, green: 0.08, blue: 0.16)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
                .ignoresSafeArea()

                VStack(spacing: 24) {
                    Lum1naLogo(size: 190)

                    Text("Lum1na")
                        .font(.largeTitle.weight(.semibold))
                        .foregroundStyle(.white)

                    Text("Experimental iOS research")
                        .font(.subheadline)
                        .foregroundStyle(.white.opacity(0.7))
                }
            }
            .navigationTitle("Lum1na")
            .toolbarColorScheme(.dark, for: .navigationBar)
        }
    }
}

#Preview {
    ContentView()
}

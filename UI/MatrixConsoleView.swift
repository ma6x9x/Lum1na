import SwiftUI

// PASTE SLOT: overwrite with your other agent's MatrixConsoleView.swift

struct MatrixConsoleView: View {
    @ObservedObject private var manager = ExploitManager.shared

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 16)
                .fill(Color.black.opacity(0.9))

            MatrixRainView()
                .opacity(0.15)
                .clipShape(RoundedRectangle(cornerRadius: 16))

            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(manager.lines) { line in
                        Text(line.text)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(line.color)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding()
            }
        }
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(
                    LinearGradient(
                        colors: [Color.purple.opacity(0.6), Color.blue.opacity(0.6)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 1.5
                )
        )
        .shadow(color: Color.purple.opacity(0.4), radius: 10)
        .overlay(alignment: .topTrailing) {
            Button {
                UIPasteboard.general.string = manager.lines.map(\.text).joined(separator: "\n")
            } label: {
                Image(systemName: "doc.on.doc")
                    .foregroundColor(.white)
                    .padding(8)
                    .background(Color.white.opacity(0.2))
                    .clipShape(Circle())
            }
            .padding(8)
        }
    }
}

struct MatrixRainView: View {
    @State private var characters: [MatrixChar] = []

    struct MatrixChar: Identifiable {
        let id = UUID()
        var x: CGFloat
        var y: CGFloat
        var char: String
        var speed: Double
        var opacity: Double
    }

    var body: some View {
        GeometryReader { geometry in
            ZStack {
                ForEach(characters) { char in
                    Text(char.char)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.green.opacity(char.opacity))
                        .position(x: char.x, y: char.y)
                }
            }
            .onAppear {
                startRain(width: geometry.size.width, height: geometry.size.height)
            }
        }
    }

    private func startRain(width: CGFloat, height: CGFloat) {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*")
        characters = (0..<30).map { _ in
            MatrixChar(
                x: CGFloat.random(in: 0...max(width, 1)),
                y: CGFloat.random(in: -100...max(height, 1)),
                char: String(alphabet.randomElement()!),
                speed: Double.random(in: 20...60),
                opacity: Double.random(in: 0.2...0.8)
            )
        }
        Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { _ in
            for i in characters.indices {
                characters[i].y += CGFloat(characters[i].speed * 0.05)
                if characters[i].y > height + 50 {
                    characters[i].y = -50
                    characters[i].x = CGFloat.random(in: 0...max(width, 1))
                    characters[i].char = String(alphabet.randomElement()!)
                }
            }
        }
    }
}

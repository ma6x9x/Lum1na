//
//  RespringSplash.swift
//  Lum1na
//
//  Dopamine-style custom respring logo. Lum1naAfterKread writes a splash
//  flag and posts Lum1naWillRespring immediately before the jbctl spawn,
//  then holds 1.5 s so this full-screen plate is visible before SpringBoard
//  restarts. The flag is consumed on the next launch for a short
//  "jailbreak active" splash after the respring completes.
//

import SwiftUI

/// Four-point star — the same hub glyph the motherboard uses.
struct LuminaFourPointStar: Shape {
    func path(in rect: CGRect) -> Path {
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let outer = min(rect.width, rect.height) / 2
        let inner = outer * 0.30
        var path = Path()
        for i in 0..<8 {
            let angle = -CGFloat.pi / 2 + CGFloat(i) * .pi / 4
            let radius = (i % 2 == 0) ? outer : inner
            let point = CGPoint(x: center.x + cos(angle) * radius,
                                y: center.y + sin(angle) * radius)
            if i == 0 { path.move(to: point) } else { path.addLine(to: point) }
        }
        path.closeSubpath()
        return path
    }
}

struct Lum1naRespringSplash: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var pulse = false

    private let pink = Color(red: 1.00, green: 0.16, blue: 0.47)
    private let violet = Color(red: 0.46, green: 0.10, blue: 0.92)

    var body: some View {
        ZStack {
            LinearGradient(colors: [pink, violet],
                           startPoint: .topLeading,
                           endPoint: .bottomTrailing)
                .ignoresSafeArea()

            RadialGradient(colors: [Color.white.opacity(0.30), .clear],
                           center: .center,
                           startRadius: 6,
                           endRadius: 230)
                .ignoresSafeArea()

            VStack(spacing: 18) {
                ZStack {
                    Circle()
                        .fill(Color.white.opacity(0.13))
                        .frame(width: 138, height: 138)
                    LuminaFourPointStar()
                        .fill(Color.white)
                        .frame(width: 88, height: 88)
                        .shadow(color: Color.white.opacity(0.6), radius: 20)
                        .scaleEffect(pulse ? 1.05 : 0.95)
                }

                Text("LUM1NA")
                    .font(.system(size: 34, weight: .heavy, design: .rounded))
                    .tracking(10)
                    .foregroundStyle(Color.white)

                Text("respringing")
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(.white.opacity(0.85))

                ProgressView()
                    .tint(.white)
                    .padding(.top, 10)
            }
            .padding(28)
        }
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.easeInOut(duration: 1.2).repeatForever(autoreverses: true)) {
                pulse = true
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("LUM1NA respringing")
    }
}

#Preview("Respring Splash") {
    Lum1naRespringSplash()
}

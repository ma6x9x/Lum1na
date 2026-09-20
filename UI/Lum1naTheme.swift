// Lum1naTheme.swift
import SwiftUI

struct LiquidGlassEffect: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(
                LinearGradient(
                    colors: [Color.purple.opacity(0.1), Color.blue.opacity(0.1), Color.purple.opacity(0.1)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
            .overlay(
                RoundedRectangle(cornerRadius: 20)
                    .stroke(
                        LinearGradient(
                            colors: [.white.opacity(0.3), .white.opacity(0.1)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 1
                    )
            )
            .blur(radius: 0.5)
            .shadow(color: .purple.opacity(0.2), radius: 10, x: 0, y: 5)
    }
}

extension View {
    func liquidGlass() -> some View {
        self.modifier(LiquidGlassEffect())
    }
}

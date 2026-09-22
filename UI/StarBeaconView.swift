import SwiftUI

struct StarBeaconView: View {
    let stage: JailbreakStage
    @State private var pulsePhase: Double = 0
    @State private var rotationAngle: Double = 0
    
    var body: some View {
        TimelineView(.animation(minimumInterval: 1/60, paused: false)) { context in
            ZStack {
                Circle()
                    .fill(
                        RadialGradient(
                            colors: [
                                stage.glowColor.opacity(0.3),
                                stage.glowColor.opacity(0.1),
                                .clear
                            ],
                            center: .center,
                            startRadius: 0,
                            endRadius: 100
                        )
                    )
                    .scaleEffect(calculateGlowScale(at: context.date))
                    .blur(radius: 25)
                
                // Renamed to avoid conflict with ContentView's FourPointedStar
                BeaconFourPointedStar()
                    .fill(
                        LinearGradient(
                            colors: [
                                stage.color.opacity(0.95),
                                stage.color.opacity(0.7),
                                stage.color.opacity(0.4)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .overlay(
                        BeaconFourPointedStar()
                            .stroke(stage.color.opacity(0.9), lineWidth: 1.5)
                    )
                    .frame(width: LayoutConstants.starSize, height: LayoutConstants.starSize)
                    .rotationEffect(.degrees(calculateCalmRotation(at: context.date)))
                    .scaleEffect(calculateCalmScale(at: context.date))
                    .shadow(color: stage.glowColor.opacity(0.6), radius: 12)
                
                BeaconFourPointedStar()
                    .fill(Color.white.opacity(0.25))
                    .frame(width: LayoutConstants.starSize * 0.35, height: LayoutConstants.starSize * 0.35)
                    .rotationEffect(.degrees(calculateCalmRotation(at: context.date)))
                    .blur(radius: 1.5)
                
                Circle()
                    .fill(stage.color.opacity(0.8))
                    .frame(width: 12, height: 12)
                    .scaleEffect(calculateCorePulse(at: context.date))
                    .shadow(color: stage.glowColor, radius: 8)
            }
        }
    }
    
    private func calculateCalmRotation(at date: Date) -> Double {
        let time = date.timeIntervalSinceReferenceDate
        return sin(time * 2 * .pi / 6.0) * 4.0
    }
    
    private func calculateCalmScale(at date: Date) -> CGFloat {
        let time = date.timeIntervalSinceReferenceDate
        let cycle = sin(time * 2 * .pi / 3.0)
        let normalized = (cycle + 1) / 2
        return 1.0 + normalized * 0.08
    }
    
    private func calculateGlowScale(at date: Date) -> CGFloat {
        let time = date.timeIntervalSinceReferenceDate
        let cycle = sin(time * 2 * .pi / 3.0)
        let normalized = (cycle + 1) / 2
        return 1.0 + normalized * 0.15
    }
    
    private func calculateCorePulse(at date: Date) -> CGFloat {
        let time = date.timeIntervalSinceReferenceDate
        let cycle = sin(time * 2 * .pi / 1.5)
        let normalized = (cycle + 1) / 2
        return 1.0 + normalized * 0.2
    }
}

// MARK: - Renamed Shape
struct BeaconFourPointedStar: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let outerRadius = min(rect.width, rect.height) / 2
        let innerRadius = outerRadius * 0.38
        
        for i in 0..<4 {
            let angle = Double(i) * .pi / 2 - .pi / 2
            let outerX = center.x + cos(angle) * outerRadius
            let outerY = center.y + sin(angle) * outerRadius
            let nextAngle = angle + .pi / 4
            let innerX = center.x + cos(nextAngle) * innerRadius
            let innerY = center.y + sin(nextAngle) * innerRadius
            
            if i == 0 {
                path.move(to: CGPoint(x: outerX, y: outerY))
            } else {
                path.addLine(to: CGPoint(x: outerX, y: outerY))
            }
            
            path.addQuadCurve(
                to: CGPoint(x: innerX, y: innerY),
                control: CGPoint(x: (outerX + innerX) / 2, y: (outerY + innerY) / 2)
            )
        }
        
        path.closeSubpath()
        return path
    }
}

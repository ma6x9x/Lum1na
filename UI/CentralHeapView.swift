import SwiftUI

struct CentralHeapView: View {
    let heapAddress: String?
    let stage: JailbreakStage
    @State private var rotation: Double = 0
    @State private var pulsePhase: CGFloat = 0
    
    var body: some View {
        // FIX: Explicitly annotate context type
        TimelineView(
            .animation(minimumInterval: 1.0 / 60.0, paused: false)
        ) { (context: TimelineViewDefaultContext) in
            ZStack {
                // Outer rotating ring
                HexagonRing(
                    isInner: false,
                    color: stage.color,
                    time: context.date
                )
                .rotationEffect(.degrees(calculateRotation(at: context.date, speed: 1)))
                
                // Inner rotating ring (opposite direction)
                HexagonRing(
                    isInner: true,
                    color: stage.color,
                    time: context.date
                )
                .rotationEffect(.degrees(-calculateRotation(at: context.date, speed: 0.7)))
                
                // Central hexagon
                HexagonShape()
                    .fill(
                        LinearGradient(
                            colors: [
                                stage.color.opacity(0.2),
                                stage.color.opacity(0.1),
                                Color(hex: "#07060F").opacity(0.8)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .overlay(
                        HexagonShape()
                            .stroke(stage.color.opacity(0.6), lineWidth: 2)
                    )
                    .frame(width: 60, height: 60)
                
                // HEAP content
                VStack(spacing: 2) {
                    Text("HEAP")
                        .font(.system(.caption2, weight: .bold))
                        .foregroundStyle(stage.color.opacity(0.7))
                    
                    Text(heapAddress ?? "0x000000000")
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(Color.white)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }
                .padding(.horizontal, 8)
            }
        }
    }
    
    private func calculateRotation(at date: Date, speed: Double) -> Double {
        let time = date.timeIntervalSinceReferenceTime
        return (time * 10 * speed).truncatingRemainder(dividingBy: 360)
    }
}

// HexagonRing and HexagonShape stay the same...
struct HexagonRing: View {
    let isInner: Bool
    let color: Color
    let time: Date
    
    var body: some View {
        Canvas { context, size in
            let center = CGPoint(x: size.width / 2, y: size.height / 2)
            let timeVal = time.timeIntervalSinceReferenceDate
            
            let baseRadius = isInner ? 45.0 : 55.0
            let radius = baseRadius + sin(timeVal * 2) * 3
            
            var path = Path()
            for i in 0..<6 {
                let angle = Double(i) * .pi / 3 - .pi / 2
                let x = center.x + cos(angle) * radius
                let y = center.y + sin(angle) * radius
                if i == 0 { path.move(to: CGPoint(x: x, y: y)) } else { path.addLine(to: CGPoint(x: x, y: y)) }
            }
            path.closeSubpath()
            
            context.stroke(path, with: .color(color.opacity(0.4)), lineWidth: isInner ? 1 : 1.5)
        }
        .frame(width: 120, height: 120)
    }
}

struct HexagonShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let radius = min(rect.width, rect.height) / 2
        for i in 0..<6 {
            let angle = Double(i) * .pi / 3 - .pi / 2
            let x = center.x + cos(angle) * radius
            let y = center.y + sin(angle) * radius
            if i == 0 { path.move(to: CGPoint(x: x, y: y)) } else { path.addLine(to: CGPoint(x: x, y: y)) }
        }
        path.closeSubpath()
        return path
    }
}

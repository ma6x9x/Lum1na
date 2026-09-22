import SwiftUI

struct CircuitBackgroundView: View {
    let stage: JailbreakStage
    @State private var flowOffset: CGFloat = 0
    
    var body: some View {
        TimelineView(.animation(minimumInterval: 1/30, paused: false)) { context in
            GeometryReader { geometry in
                ZStack {
                    CircuitGrid(size: geometry.size, stage: stage, time: context.date)
                    RadialHexPattern(center: CGPoint(x: geometry.size.width/2, y: geometry.size.height/2), stage: stage, time: context.date)
                    EnergyFlowLines(size: geometry.size, stage: stage, time: context.date)
                }
            }
        }
    }
}

struct CircuitGrid: View {
    let size: CGSize
    let stage: JailbreakStage
    let time: Date
    let gridSpacing: CGFloat = 40
    
    var body: some View {
        Canvas { context, _ in
            let rows = Int(size.height / gridSpacing) + 2
            let cols = Int(size.width / gridSpacing) + 2
            
            for row in 0..<rows {
                let y = CGFloat(row) * gridSpacing
                var path = Path()
                path.move(to: CGPoint(x: 0, y: y))
                path.addLine(to: CGPoint(x: size.width, y: y))
                let isActive = sin(time.timeIntervalSinceReferenceDate * 0.5 + Double(row) * 0.3) > 0.7
                context.stroke(path, with: .color(isActive ? stage.color.opacity(0.4) : .circuitLine), lineWidth: 1.5)
            }
            
            for col in 0..<cols {
                let x = CGFloat(col) * gridSpacing
                var path = Path()
                path.move(to: CGPoint(x: x, y: 0))
                path.addLine(to: CGPoint(x: x, y: size.height))
                let isActive = sin(time.timeIntervalSinceReferenceDate * 0.5 + Double(col) * 0.3) > 0.7
                context.stroke(path, with: .color(isActive ? stage.color.opacity(0.4) : .circuitLine), lineWidth: 1.5)
            }
        }
    }
}

struct RadialHexPattern: View {
    let center: CGPoint
    let stage: JailbreakStage
    let time: Date
    
    var body: some View {
        Canvas { context, _ in
            for ring in 1...5 {
                drawHexagonRing(in: &context, center: center, radius: CGFloat(ring) * 50.0, ringIndex: ring, time: time)
            }
            for i in 0..<6 {
                drawRadialLine(in: &context, center: center, angle: Double(i) * .pi / 3, time: time)
            }
        }
    }
    
    private func drawHexagonRing(in context: inout GraphicsContext, center: CGPoint, radius: CGFloat, ringIndex: Int, time: Date) {
        var path = Path()
        let timeVal = time.timeIntervalSinceReferenceDate
        for i in 0..<6 {
            let angle = Double(i) * .pi / 3 - .pi / 6
            let x = center.x + cos(angle) * radius
            let y = center.y + sin(angle) * radius
            if i == 0 { path.move(to: CGPoint(x: x, y: y)) } else { path.addLine(to: CGPoint(x: x, y: y)) }
        }
        path.closeSubpath()
        let phase = timeVal * 0.5 + Double(ringIndex) * 0.4
        let opacity = (sin(phase) + 1) / 2 * 0.5 + 0.2
        context.stroke(path, with: .color(stage.color.opacity(opacity)), lineWidth: 1.5)
    }
    
    private func drawRadialLine(in context: inout GraphicsContext, center: CGPoint, angle: Double, time: Date) {
        let timeVal = time.timeIntervalSinceReferenceDate
        var path = Path()
        let startX = center.x + cos(angle) * 60.0
        let startY = center.y + sin(angle) * 60.0
        let endX = center.x + cos(angle) * 250.0
        let endY = center.y + sin(angle) * 250.0
        path.move(to: CGPoint(x: startX, y: startY))
        path.addLine(to: CGPoint(x: endX, y: endY))
        let phase = timeVal * 0.8 + angle
        let opacity = (sin(phase) + 1) / 2 * 0.6 + 0.1
        context.stroke(path, with: .color(stage.color.opacity(opacity)), lineWidth: 1)
    }
}

struct EnergyFlowLines: View {
    let size: CGSize
    let stage: JailbreakStage
    let time: Date
    
    var body: some View {
        Canvas { context, _ in
            let timeVal = time.timeIntervalSinceReferenceDate
            let center = CGPoint(x: size.width / 2, y: size.height / 2)
            for i in 0..<8 {
                let angle = Double(i) * .pi / 4
                let speed = 30.0 + Double(i) * 5
                let baseRadius = 80.0 + sin(timeVal * 0.5 + Double(i)) * 40
                let travel = fmod(timeVal * speed, 180)
                let radius = baseRadius + travel
                let x = center.x + cos(angle) * radius
                let y = center.y + sin(angle) * radius
                context.fill(Path(ellipseIn: CGRect(x: x - 4, y: y - 4, width: 8, height: 8)), with: .color(stage.color.opacity(0.8)))
            }
        }
    }
}

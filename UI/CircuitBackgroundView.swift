import SwiftUI

struct CircuitBackgroundView: View {
    let stage: JailbreakStage
    @State private var flowOffset: CGFloat = 0
    
    var body: some View {
        TimelineView(.animation(minimumInterval: 1/60, paused: false)) { context in
            GeometryReader { geometry in
                ZStack {
                    Color(hex: "#07060F").ignoresSafeArea()
                    
                    PCBTraceGrid(size: geometry.size, stage: stage, time: context.date)
                    EnergyNodes(size: geometry.size, stage: stage, time: context.date)
                    DataFlowPaths(size: geometry.size, stage: stage, time: context.date)
                    
                    RadialGradient(
                        colors: [.clear, Color(hex: "#07060F").opacity(0.7)],
                        center: .center,
                        startRadius: 100,
                        endRadius: 400
                    )
                }
            }
        }
    }
}

struct PCBTraceGrid: View {
    let size: CGSize
    let stage: JailbreakStage
    let time: Date
    let gridSpacing: CGFloat = 25
    
    var body: some View {
        Canvas { context, _ in
            let timeVal = time.timeIntervalSinceReferenceDate
            
            for row in 0..<Int(size.height / gridSpacing) + 2 {
                let y = CGFloat(row) * gridSpacing
                var path = Path()
                var currentX: CGFloat = 0
                path.move(to: CGPoint(x: 0, y: y))
                
                while currentX < size.width {
                    let segmentLength = CGFloat.random(in: 30...80)
                    let nextX = min(currentX + segmentLength, size.width)
                    
                    if Int(nextX) % 100 < 20 {
                        path.addLine(to: CGPoint(x: nextX, y: y))
                        path.addLine(to: CGPoint(x: nextX, y: y + 8))
                        path.addLine(to: CGPoint(x: nextX, y: y))
                    } else {
                        path.addLine(to: CGPoint(x: nextX, y: y))
                    }
                    currentX = nextX
                }
                
                let phase = timeVal * 0.3 + Double(row) * 0.15
                let isActive = sin(phase) > 0.6
                let opacity = isActive ? 0.5 : 0.15
                let lineWidth: CGFloat = isActive ? 2.0 : 1.0
                
                context.stroke(
                    path,
                    with: .color(isActive ? stage.color.opacity(opacity) : Color(hex: "#1E3A5F").opacity(opacity)),
                    lineWidth: lineWidth
                )
            }
            
            for col in 0..<Int(size.width / gridSpacing) + 2 {
                let x = CGFloat(col) * gridSpacing + (sin(Double(col) * 0.5) * 10)
                var path = Path()
                var currentY: CGFloat = 0
                path.move(to: CGPoint(x: x, y: 0))
                
                while currentY < size.height {
                    let segmentLength = CGFloat.random(in: 40...100)
                    let nextY = min(currentY + segmentLength, size.height)
                    path.addLine(to: CGPoint(x: x, y: nextY))
                    currentY = nextY
                }
                
                let phase = timeVal * 0.25 + Double(col) * 0.2
                let isActive = sin(phase) > 0.5
                let opacity = isActive ? 0.4 : 0.12
                
                context.stroke(
                    path,
                    with: .color(isActive ? stage.color.opacity(opacity) : Color(hex: "#1E3A5F").opacity(opacity)),
                    lineWidth: 1.0
                )
            }
            
            for row in stride(from: 0, to: Int(size.height / gridSpacing), by: 3) {
                for col in stride(from: 0, to: Int(size.width / gridSpacing), by: 4) {
                    let x = CGFloat(col) * gridSpacing
                    let y = CGFloat(row) * gridSpacing
                    
                    let phase = timeVal * 0.5 + Double(row + col) * 0.1
                    let isPulsing = sin(phase) > 0.7
                    
                    let nodeSize: CGFloat = isPulsing ? 4.0 : 2.5
                    let nodeOpacity = isPulsing ? 0.8 : 0.4
                    
                    let rect = CGRect(x: x - nodeSize/2, y: y - nodeSize/2, width: nodeSize, height: nodeSize)
                    
                    context.fill(
                        Path(ellipseIn: rect),
                        with: .color(isPulsing ? stage.color.opacity(nodeOpacity) : Color(hex: "#334155").opacity(nodeOpacity))
                    )
                }
            }
        }
    }
}

struct EnergyNodes: View {
    let size: CGSize
    let stage: JailbreakStage
    let time: Date
    
    var body: some View {
        Canvas { context, _ in
            let timeVal = time.timeIntervalSinceReferenceDate
            let center = CGPoint(x: size.width / 2, y: size.height / 2)
            
            for i in 0..<12 {
                let angle = Double(i) * .pi / 6 + timeVal * 0.3
                let radius = 100.0 + Double(i) * 15 + sin(timeVal + Double(i)) * 20
                
                let x = center.x + cos(angle) * CGFloat(radius)
                let y = center.y + sin(angle) * CGFloat(radius) * 0.6
                
                guard x > 0 && x < size.width && y > 0 && y < size.height else { continue }
                
                let pulse = (sin(timeVal * 3 + Double(i)) + 1) / 2
                let nodeSize = 3.0 + pulse * 4.0
                let opacity = 0.4 + pulse * 0.6
                
                let rect = CGRect(x: x - CGFloat(nodeSize)/2, y: y - CGFloat(nodeSize)/2, width: CGFloat(nodeSize), height: CGFloat(nodeSize))
                let glowRect = CGRect(x: x - CGFloat(nodeSize), y: y - CGFloat(nodeSize), width: CGFloat(nodeSize * 2), height: CGFloat(nodeSize * 2))
                
                context.fill(Path(ellipseIn: glowRect), with: .color(stage.color.opacity(opacity * 0.3)))
                context.fill(Path(ellipseIn: rect), with: .color(stage.color.opacity(opacity)))
            }
            
            let corePulse = (sin(timeVal * 2) + 1) / 2
            let coreSize = 8.0 + corePulse * 6.0
            let coreRect = CGRect(x: center.x - CGFloat(coreSize)/2, y: center.y - CGFloat(coreSize)/2, width: CGFloat(coreSize), height: CGFloat(coreSize))
            
            context.fill(Path(ellipseIn: coreRect), with: .color(stage.color.opacity(0.9)))
        }
    }
}

struct DataFlowPaths: View {
    let size: CGSize
    let stage: JailbreakStage
    let time: Date
    
    var body: some View {
        Canvas { context, _ in
            let timeVal = time.timeIntervalSinceReferenceDate
            
            for i in 0..<8 {
                let angle = Double(i) * .pi / 4 + timeVal * 0.1
                let startRadius = max(size.width, size.height) / 2
                let startX = size.width/2 + cos(angle) * CGFloat(startRadius)
                let startY = size.height/2 + sin(angle) * CGFloat(startRadius) * 0.8
                
                let flowProgress = fmod(timeVal * 0.3 + Double(i) * 0.125, 1.0)
                let currentRadius = startRadius * (1.0 - flowProgress)
                
                let currentX = size.width/2 + cos(angle) * CGFloat(currentRadius)
                let currentY = size.height/2 + sin(angle) * CGFloat(currentRadius) * 0.8
                
                let packetSize = 6.0 * (1.0 - flowProgress * 0.5)
                let opacity = 1.0 - flowProgress * 0.7
                
                let rect = CGRect(x: currentX - CGFloat(packetSize)/2, y: currentY - CGFloat(packetSize)/2, width: CGFloat(packetSize), height: CGFloat(packetSize))
                
                context.fill(Path(ellipseIn: rect), with: .color(stage.color.opacity(opacity)))
                
                for trail in 1...3 {
                    let trailRadius = currentRadius + CGFloat(trail * 15)
                    let trailX = size.width/2 + cos(angle) * trailRadius
                    let trailY = size.height/2 + sin(angle) * trailRadius * 0.8
                    let trailOpacity = opacity * (0.5 - Double(trail) * 0.15)
                    
                    let trailRect = CGRect(x: trailX - 2, y: trailY - 2, width: 4, height: 4)
                    context.fill(Path(ellipseIn: trailRect), with: .color(stage.color.opacity(trailOpacity)))
                }
            }
        }
    }
}

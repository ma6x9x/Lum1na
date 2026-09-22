import SwiftUI

struct CentralHeapView: View {
    let heapAddress: String?
    let stage: JailbreakStage
    
    var body: some View {
        TimelineView(.animation(minimumInterval: 1/60, paused: false)) { context in
            ZStack {
                HexagonRing(isInner: false, color: stage.color, time: context.date)
                    .rotationEffect(.degrees(calculateRotation(at: context.date, speed: 1)))
                HexagonRing(isInner: true, color: stage.color, time: context.date)
                    .rotationEffect(.degrees(-calculateRotation(at: context.date, speed: 0.7)))
                HexagonShape()
                    .fill(LinearGradient(colors: [stage.color.opacity(0.2), stage.color.opacity(0.1), .lum1naField.opacity(0.8)], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .overlay(HexagonShape().stroke(stage.color.opacity(0.6), lineWidth: 2))
                    .frame(width: LayoutConstants.hexagonSize, height: LayoutConstants.hexagonSize)
                VStack(spacing: 2) {
                    Text("HEAP").font(.system(.caption2, weight: .bold)).foregroundStyle(stage.color.opacity(0.7))
                    Text(heapAddress ?? "0x000000000").font(.heapAddress).foregroundStyle(.consoleText).lineLimit(1).minimumScaleFactor(0.8)
                }.padding(.horizontal, 8)
            }
        }
    }
    
    private func calculateRotation(at date: Date, speed: Double) -> Double {
        let time = date.timeIntervalSinceReferenceDate
        return (time * 10 * speed).truncatingRemainder(dividingBy: 360)
    }
}

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
            
            for i in 0..<6 {
                let angle = Double(i) * .pi / 3 - .pi / 2
                let x = center.x + cos(angle) * radius
                let y = center.y + sin(angle) * radius
                let nodeSize: CGFloat = isInner ? 4 : 6
                let nodeRect = CGRect(x: x - nodeSize/2, y: y - nodeSize/2, width: nodeSize, height: nodeSize)
                let nodePhase = timeVal * 3 + Double(i) * 0.5
                let nodeOpacity = (sin(nodePhase) + 1) / 2 * 0.6 + 0.2
                context.fill(Path(ellipseIn: nodeRect), with: .color(color.opacity(nodeOpacity)))
            }
        }.frame(width: 120, height: 120)
    }
}

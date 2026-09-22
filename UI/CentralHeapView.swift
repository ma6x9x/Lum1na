import SwiftUI

struct CentralHeapView: View {
    let heapAddress: String?
    let stage: JailbreakStage
    
    var body: some View {
        VStack(spacing: 8) {
            StatusIndicator(stage: stage)
            
            Text("HEAP")
                .font(.system(size: 11, weight: .bold, design: .rounded))
                .foregroundStyle(stage.color.opacity(0.7))
                .tracking(2)
            
            Text(heapAddress ?? "0x000000000000")
                .font(.system(.callout, design: .monospaced))
                .foregroundStyle(Color.white)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(Color(hex: "#0A0A0F").opacity(0.8))
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .stroke(stage.color.opacity(0.4), lineWidth: 1)
                        )
                )
            
            Text(statusText)
                .font(.system(.caption2, weight: .medium))
                .foregroundStyle(statusColor)
        }
    }
    
    private var statusText: String {
        guard let _ = heapAddress else { return "AWAITING LEAK" }
        return "MAPPED"
    }
    
    private var statusColor: Color {
        guard heapAddress != nil else { return Color(hex: "#64748B") }
        return Color(hex: "#10B981")
    }
}

struct StatusIndicator: View {
    let stage: JailbreakStage
    @State private var pulseScale: CGFloat = 1.0
    
    var body: some View {
        ZStack {
            Circle()
                .stroke(stage.color.opacity(0.3), lineWidth: 2)
                .frame(width: 16, height: 16)
            
            Circle()
                .fill(stage.color)
                .frame(width: 8, height: 8)
                .scaleEffect(pulseScale)
                .shadow(color: stage.glowColor, radius: 4)
        }
        .onAppear {
            withAnimation(.easeInOut(duration: 1.5).repeatForever(autoreverses: true)) {
                pulseScale = 1.2
            }
        }
    }
}

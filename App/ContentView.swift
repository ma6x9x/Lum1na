import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()
    
    var body: some View {
        ZStack {
            // Background
            Color(hex: "07060F")
                .ignoresSafeArea()
                .overlay(GridPattern().opacity(0.03))
            
            // Main content
            ScrollView(.vertical, showsIndicators: false) {
                VStack(spacing: 0) {
                    // Header
                    HeaderView()
                        .padding(.top, 60)
                    
                    // Star beacon
                    StarBeaconSection(viewModel: viewModel)
                        .padding(.top, 20)
                    
                    // Tagline
                    Text("The guiding light for Jailbreaks")
                        .font(.system(size: 16, weight: .medium))
                        .foregroundStyle(.secondary)
                        .padding(.top, 16)
                    
                    // Console card
                    ConsoleCard(viewModel: viewModel)
                        .padding(.horizontal, 20)
                        .padding(.top, 24)
                    
                    // Device info
                    DeviceInfoCard()
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    // Stage buttons
                    StageButtonsRow(viewModel: viewModel)
                        .padding(.horizontal, 16)
                        .padding(.top, 20)
                    
                    // Action buttons
                    ActionButtons(viewModel: viewModel)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    // Status
                    StatusBar(viewModel: viewModel)
                        .padding(.top, 20)
                        .padding(.bottom, 40)
                }
            }
        }
    }
}

// MARK: - Supporting Views

struct HeaderView: View {
    var body: some View {
        VStack(spacing: 4) {
            Text("Lum1na")
                .font(.system(size: 42, weight: .bold, design: .rounded))
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color(hex: "FF6B9D"), Color(hex: "4ECDC4")],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
            
            Text("v0.1 • private beta")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.gray)
        }
    }
}

struct StarBeaconSection: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @State private var isPulsing = false
    
    var body: some View {
        ZStack {
            Circle()
                .fill(.ultraThinMaterial)
                .frame(width: 200, height: 200)
                .overlay(
                    Circle()
                        .stroke(
                            LinearGradient(
                                colors: [Color(hex: "FF6B9D"), Color(hex: "4ECDC4")],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            ),
                            lineWidth: 3
                        )
                )
            
            StarShape(points: 4, innerRadius: 0.4)
                .fill(
                    LinearGradient(
                        colors: [Color(hex: "FF6B9D"), Color(hex: "9B59B6"), Color(hex: "4ECDC4")],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .frame(width: 80, height: 80)
                .shadow(color: Color(hex: "9B59B6").opacity(0.8), radius: 20)
                .scaleEffect(isPulsing ? 1.05 : 1.0)
                .animation(.easeInOut(duration: 2).repeatForever(autoreverses: true), value: isPulsing)
        }
        .frame(height: 220)
        .onAppear { isPulsing = true }
    }
}

struct ConsoleCard: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label("console", systemImage: "terminal")
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
                
                Spacer()
                
                Button(action: {
                    UIPasteboard.general.string = viewModel.consoleText
                }) {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 14))
                        .foregroundStyle(.secondary)
                        .padding(8)
                        .background(.ultraThinMaterial)
                        .clipShape(Circle())
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            
            Divider().background(Color.white.opacity(0.1))
            
            ScrollView(.vertical, showsIndicators: true) {
                Text(viewModel.consoleText)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.cyan)
                    .lineSpacing(4)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
            }
            .frame(height: 180)
        }
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 20)
                        .stroke(Color(hex: "FF6B9D").opacity(0.3), lineWidth: 1)
                )
        )
    }
}

struct DeviceInfoCard: View {
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "iphone")
                .font(.system(size: 24))
                .foregroundStyle(Color(hex: "FF6B9D"))
                .frame(width: 44, height: 44)
                .background(RoundedRectangle(cornerRadius: 12).fill(.ultraThinMaterial))
            
            VStack(alignment: .leading, spacing: 2) {
                Text("iPhone").font(.system(size: 17, weight: .semibold))
                Text("iOS 26.5").font(.system(size: 14)).foregroundStyle(.secondary)
            }
            
            Spacer()
            
            Circle().fill(Color(hex: "4ECDC4")).frame(width: 8, height: 8)
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 16).fill(.ultraThinMaterial))
    }
}

struct StageButtonsRow: View {
    @ObservedObject var viewModel: Lum1naViewModel
    let stages = [("KASLR", "memorychip"), ("Heap", "cpu"), ("ANE", "brain"), ("PPL", "lock"), ("Persist", "arrow")]
    
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(stages, id: \.0) { stage in
                    StageButton(
                        title: stage.0,
                        icon: stage.1,
                        isActive: viewModel.activeStages.contains(stage.0)
                    )
                }
            }
            .padding(.horizontal, 4)
        }
    }
}

struct StageButton: View {
    let title: String
    let icon: String
    let isActive: Bool
    
    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: icon).font(.system(size: 16))
            Text(title).font(.system(size: 11, weight: .medium))
        }
        .foregroundStyle(isActive ? .white : .secondary)
        .frame(width: 64, height: 56)
        .background(
            Capsule()
                .fill(isActive ? Color(hex: "9B59B6").opacity(0.3) : .ultraThinMaterial)
                .overlay(Capsule().stroke(isActive ? Color(hex: "FF6B9D") : Color.white.opacity(0.1), lineWidth: isActive ? 2 : 1))
        )
    }
}

struct ActionButtons: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        HStack(spacing: 12) {
            Button(action: { viewModel.showStages.toggle() }) {
                Text("Hide stages")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.primary)
                    .frame(maxWidth: .infinity, height: 52)
                    .background(Capsule().fill(.ultraThinMaterial))
            }
            
            Button(action: { viewModel.startJailbreak() }) {
                Text("Jailbreak")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity, height: 52)
                    .background(
                        Capsule()
                            .fill(LinearGradient(colors: [Color(hex: "FF6B9D"), Color(hex: "9B59B6")], startPoint: .leading, endPoint: .trailing))
                    )
            }
            .disabled(viewModel.isRunning)
            .opacity(viewModel.isRunning ? 0.6 : 1)
        }
    }
}

struct StatusBar: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var statusColor: Color {
        switch viewModel.status {
        case .ready: return Color(hex: "4ECDC4")
        case .running: return Color(hex: "F39C12")
        case .completed: return Color(hex: "27AE60")
        case .error: return Color(hex: "E74C3C")
        }
    }
    
    var body: some View {
        HStack(spacing: 8) {
            Circle().fill(statusColor).frame(width: 8, height: 8)
            Text(viewModel.statusText).font(.system(size: 14, weight: .medium)).foregroundStyle(.secondary)
            Spacer()
            Text("\(viewModel.consoleLines) lines").font(.system(size: 12)).foregroundStyle(.gray)
        }
        .padding(.horizontal, 20)
    }
}

// Supporting shapes and extensions
struct StarShape: Shape {
    let points: Int
    let innerRadius: CGFloat
    
    func path(in rect: CGRect) -> Path {
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let outerRadius = min(rect.width, rect.height) / 2
        let inner = outerRadius * innerRadius
        var path = Path()
        
        for i in 0..<(points * 2) {
            let angle = CGFloat(i) * .pi / CGFloat(points) - .pi / 2
            let radius = i % 2 == 0 ? outerRadius : inner
            let x = center.x + cos(angle) * radius
            let y = center.y + sin(angle) * radius
            
            if i == 0 { path.move(to: CGPoint(x: x, y: y)) }
            else { path.addLine(to: CGPoint(x: x, y: y)) }
        }
        path.closeSubpath()
        return path
    }
}

struct GridPattern: View {
    var body: some View {
        GeometryReader { geometry in
            Canvas { context, size in
                let gridSize: CGFloat = 40
                for row in 0..<Int(size.height / gridSize) + 1 {
                    for col in 0..<Int(size.width / gridSize) + 1 {
                        let dot = Path(ellipseIn: CGRect(x: CGFloat(col) * gridSize - 1, y: CGFloat(row) * gridSize - 1, width: 2, height: 2))
                        context.fill(dot, with: .color(.white.opacity(0.5)))
                    }
                }
            }
        }
    }
}

extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3: (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default: (a, r, g, b) = (1, 1, 1, 0)
        }
        self.init(.sRGB, red: Double(r) / 255, green: Double(g) / 255, blue: Double(b) / 255, opacity: Double(a) / 255)
    }
}

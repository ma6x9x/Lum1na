import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()
    
    var body: some View {
        ZStack {
            Color(hex: "07060F")
                .ignoresSafeArea()
            
            ScrollView(.vertical, showsIndicators: false) {
                VStack(spacing: 0) {
                    HeaderView()
                        .padding(.top, 50)
                    
                    StarBeaconSection(viewModel: viewModel)
                        .padding(.top, 20)
                    
                    Text("The guiding light for Jailbreaks")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundStyle(.secondary)
                        .padding(.top, 12)
                    
                    DeviceInfoCard()
                        .padding(.horizontal, 20)
                        .padding(.top, 20)
                    
                    ConsoleCard(viewModel: viewModel)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    StageButtonsRow(viewModel: viewModel)
                        .padding(.horizontal, 16)
                        .padding(.top, 16)
                    
                    ActionButtons(viewModel: viewModel)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    StatusBar(viewModel: viewModel)
                        .padding(.top, 16)
                        .padding(.bottom, 30)
                }
            }
        }
    }
}

// MARK: - Header
struct HeaderView: View {
    var body: some View {
        VStack(spacing: 4) {
            Text("LUM1NA")
                .font(.system(size: 36, weight: .black, design: .rounded))
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color(hex: "FF6B9D"), Color(hex: "C44569"), Color(hex: "4ECDC4")],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
            
            Text("v0.1 • private beta")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.gray)
        }
    }
}

// MARK: - Star Beacon
struct StarBeaconSection: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @State private var pulse = false
    
    var body: some View {
        ZStack {
            Circle()
                .stroke(
                    LinearGradient(colors: [Color(hex: "FF6B9D"), Color(hex: "4ECDC4")], startPoint: .topLeading, endPoint: .bottomTrailing),
                    lineWidth: 2
                )
                .frame(width: 180, height: 180)
            
            FourPointedStar()
                .fill(
                    LinearGradient(colors: [Color(hex: "FF6B9D"), Color(hex: "9B59B6"), Color(hex: "4ECDC4")], startPoint: .top, endPoint: .bottom)
                )
                .frame(width: 70, height: 70)
                .shadow(color: Color(hex: "9B59B6").opacity(0.6), radius: 15)
                .scaleEffect(pulse ? 1.08 : 1.0)
                .animation(.easeInOut(duration: 2).repeatForever(autoreverses: true), value: pulse)
        }
        .frame(height: 200)
        .onAppear { pulse = true }
    }
}

struct FourPointedStar: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let outer = min(rect.width, rect.height) / 2
        let inner = outer * 0.35
        
        for i in 0..<8 {
            let angle = CGFloat(i) * .pi / 4 - .pi / 2
            let radius = i % 2 == 0 ? outer : inner
            let x = center.x + cos(angle) * radius
            let y = center.y + sin(angle) * radius
            i == 0 ? path.move(to: CGPoint(x: x, y: y)) : path.addLine(to: CGPoint(x: x, y: y))
        }
        path.closeSubpath()
        return path
    }
}

// MARK: - Device Info with Detection
struct DeviceInfoCard: View {
    @State private var deviceInfo = DeviceDetector.getInfo()
    
    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(deviceInfo.isSupported ? Color(hex: "27AE60").opacity(0.2) : Color(hex: "E74C3C").opacity(0.2))
                    .frame(width: 44, height: 44)
                
                Image(systemName: deviceInfo.icon)
                    .font(.system(size: 20))
                    .foregroundStyle(deviceInfo.isSupported ? Color(hex: "27AE60") : Color(hex: "E74C3C"))
            }
            
            VStack(alignment: .leading, spacing: 2) {
                Text(deviceInfo.modelName)
                    .font(.system(size: 16, weight: .semibold))
                
                Text("iOS \(deviceInfo.osVersion) • Build \(deviceInfo.buildVersion)")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            VStack(alignment: .trailing, spacing: 2) {
                Text(deviceInfo.chipName)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.secondary)
                
                HStack(spacing: 4) {
                    Circle()
                        .fill(deviceInfo.isSupported ? Color(hex: "27AE60") : Color(hex: "E74C3C"))
                        .frame(width: 6, height: 6)
                    
                    Text(deviceInfo.isSupported ? "Supported" : "Unsupported")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(deviceInfo.isSupported ? Color(hex: "27AE60") : Color(hex: "E74C3C"))
                }
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(deviceInfo.isSupported ? Color(hex: "27AE60").opacity(0.3) : Color(hex: "E74C3C").opacity(0.3), lineWidth: 1)
                )
        )
        .padding(.horizontal, 20)
    }
}

// MARK: - Device Detector
struct DeviceDetector {
    static func getInfo() -> DeviceInfo {
        let device = UIDevice.current
        let model = device.model
        let systemVersion = device.systemVersion
        
        // Get actual device identifier using sysctl
        var systemInfo = utsname()
        uname(&systemInfo)
        let machineMirror = Mirror(reflecting: systemInfo.machine)
        let identifier = machineMirror.children.reduce("") { identifier, element in
            guard let value = element.value as? Int8, value != 0 else { return identifier }
            return identifier + String(UnicodeScalar(UInt8(value)))
        }
        
        // Map identifier to actual device name
        let modelName = mapIdentifierToName(identifier)
        let chipName = mapIdentifierToChip(identifier)
        let isSupported = checkSupport(identifier: identifier, version: systemVersion)
        
        return DeviceInfo(
            modelName: modelName,
            chipName: chipName,
            osVersion: systemVersion,
            buildVersion: getBuildVersion(),
            identifier: identifier,
            icon: getIcon(for: identifier),
            isSupported: isSupported
        )
    }
    
    static func mapIdentifierToName(_ id: String) -> String {
        let map = [
            "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
            "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
            "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
            "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
            "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
            "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max",
            "iPhone15,4": "iPhone 15", "iPhone15,5": "iPhone 15 Plus",
            "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
            "iPad8,1": "iPad Pro 11\" (1st gen)", "iPad8,2": "iPad Pro 11\" (1st gen)",
            "iPad8,3": "iPad Pro 11\" (1st gen)", "iPad8,4": "iPad Pro 11\" (1st gen)",
            "iPad8,5": "iPad Pro 12.9\" (3rd gen)", "iPad8,6": "iPad Pro 12.9\" (3rd gen)",
            "iPad8,7": "iPad Pro 12.9\" (3rd gen)", "iPad8,8": "iPad Pro 12.9\" (3rd gen)",
            "iPad8,9": "iPad Pro 11\" (2nd gen)", "iPad8,10": "iPad Pro 11\" (2nd gen)",
            "iPad8,11": "iPad Pro 12.9\" (4th gen)", "iPad8,12": "iPad Pro 12.9\" (4th gen)",
        ]
        return map[id] ?? id
    }
    
    static func mapIdentifierToChip(_ id: String) -> String {
        if id.contains("iPhone13") { return "A14 Bionic" }
        if id.contains("iPhone14") && !id.contains("iPhone14,7") && !id.contains("iPhone14,8") { return "A15 Bionic" }
        if id.contains("iPhone15") { return "A16 Bionic" }
        if id.contains("iPhone16") { return "A17 Pro" }
        if id.contains("iPad8") { return "A12X/Z Bionic" }
        return "Unknown"
    }
    
    static func checkSupport(identifier: String, version: String) -> Bool {
        let supportedDevices = [
            "iPhone13,1", "iPhone13,2", "iPhone13,3", "iPhone13,4", // A14
            "iPhone14,4", "iPhone14,5", "iPhone14,2", "iPhone14,3", // A15
            "iPhone14,7", "iPhone14,8", "iPhone15,2", "iPhone15,3", // A15/A16
            "iPhone15,4", "iPhone15,5", "iPhone16,1", "iPhone16,2", // A16/A17
            "iPad8,5", "iPad8,6", "iPad8,7", "iPad8,8", // A12X
        ]
        return supportedDevices.contains(identifier)
    }
    
    static func getBuildVersion() -> String {
        var build = ""
        if let info = Bundle.main.infoDictionary?["CFBundleVersion"] as? String {
            build = info
        }
        return build
    }
    
    static func getIcon(for id: String) -> String {
        if id.contains("iPad") { return "ipad" }
        return "iphone"
    }
}

struct DeviceInfo {
    let modelName: String
    let chipName: String
    let osVersion: String
    let buildVersion: String
    let identifier: String
    let icon: String
    let isSupported: Bool
}

// MARK: - Console
struct ConsoleCard: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label("console", systemImage: "terminal")
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
                
                Spacer()
                
                Button(action: {
                    UIPasteboard.general.string = viewModel.consoleText
                }) {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            
            Divider().background(Color.white.opacity(0.1))
            
            ScrollView(.vertical, showsIndicators: true) {
                Text(viewModel.consoleText)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Color(hex: "4ECDC4"))
                    .lineSpacing(3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .frame(height: 160)
        }
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(hex: "0A0A0F"))
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color(hex: "1E293B"), lineWidth: 1))
        )
    }
}

// MARK: - Stage Buttons
struct StageButtonsRow: View {
    @ObservedObject var viewModel: Lum1naViewModel
    let stages = [
        ("KASLR", "memorychip", "Kernel slide detection"),
        ("Heap", "cpu", "Memory corruption setup"),
        ("ANE", "brain.head.profile", "Neural Engine exploit"),
        ("PPL", "lock.shield", "Page protection bypass"),
        ("Persist", "arrow.clockwise", "Install persistence")
    ]
    
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 10) {
                ForEach(stages, id: \.0) { stage in
                    DashboardStageButton(
                        title: stage.0,
                        icon: stage.1,
                        description: stage.2,
                        isActive: viewModel.activeStage == stage.0,
                        isCompleted: viewModel.completedStages.contains(stage.0)
                    )
                }
            }
            .padding(.horizontal, 4)
        }
    }
}

struct DashboardStageButton: View {
    let title: String
    let icon: String
    let description: String
    let isActive: Bool
    let isCompleted: Bool
    
    var body: some View {
        VStack(spacing: 6) {
            ZStack {
                Circle()
                    .fill(backgroundFill)
                    .frame(width: 40, height: 40)
                
                Image(systemName: isCompleted ? "checkmark" : icon)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(foregroundColor)
            }
            
            Text(title)
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(foregroundColor)
        }
        .frame(width: 70, height: 70)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(hex: "0A0A0F"))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(borderColor, lineWidth: isActive ? 2 : 1)
                )
        )
    }
    
    var backgroundFill: Color {
        if isCompleted { return Color(hex: "27AE60").opacity(0.3) }
        if isActive { return Color(hex: "9B59B6").opacity(0.3) }
        return Color(hex: "1E293B")
    }
    
    var foregroundColor: Color {
        if isCompleted { return Color(hex: "27AE60") }
        if isActive { return Color(hex: "FF6B9D") }
        return .gray
    }
    
    var borderColor: Color {
        if isCompleted { return Color(hex: "27AE60") }
        if isActive { return Color(hex: "FF6B9D") }
        return Color(hex: "1E293B")
    }
}

// MARK: - Action Buttons
struct ActionButtons: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        HStack(spacing: 12) {
            Button(action: { viewModel.showStages.toggle() }) {
                Text(viewModel.showStages ? "Hide stages" : "Show stages")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.primary)
                    .frame(maxWidth: .infinity)
                    .frame(height: 48)
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(Color(hex: "1E293B"))
                    )
            }
            
            Button(action: { viewModel.startJailbreak() }) {
                Text(viewModel.isRunning ? "Running..." : "Jailbreak")
                    .font(.system(size: 15, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 48)
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(
                                LinearGradient(
                                    colors: viewModel.isRunning ? [Color.gray] : [Color(hex: "FF6B9D"), Color(hex: "9B59B6")],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                    )
            }
            .disabled(viewModel.isRunning)
        }
    }
}

// MARK: - Status Bar
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
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
            
            Text(viewModel.statusText)
                .font(.system(size: 13, weight: .medium))
            
            Spacer()
            
            Text("\(viewModel.consoleLines) events")
                .font(.system(size: 11))
                .foregroundStyle(.gray)
        }
        .padding(.horizontal, 20)
    }
}

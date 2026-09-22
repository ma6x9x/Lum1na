import SwiftUI

enum LogLevel: String {
    case info = "[*]"
    case success = "[+]"
    case warning = "[!]"
    case error = "[-]"
    case debug = "[#]"
    
    var color: Color {
        switch self {
        case .info:     return Color(hex: "#22D3EE")
        case .success:  return Color(hex: "#4ADE80")
        case .warning:  return Color(hex: "#FBBF24")
        case .error:    return Color(hex: "#F87171")
        case .debug:    return Color(hex: "#64748B")
        }
    }
}

struct LogEntry: Identifiable {
    let id = UUID()
    let timestamp: Date
    let level: LogLevel
    let message: String
    
    var formattedTimestamp: String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter.string(from: timestamp)
    }
}

struct MatrixConsoleView: View {
    @State private var logs: [LogEntry] = []
    @State private var autoScroll = true
    
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("console").font(.system(.caption, design: .monospaced)).foregroundStyle(Color(hex: "#64748B"))
                Spacer()
                HStack(spacing: 8) {
                    Circle().fill(Color(hex: "#4ADE80")).frame(width: 6, height: 6)
                    Text("online").font(.system(.caption2, design: .monospaced)).foregroundStyle(Color(hex: "#4ADE80").opacity(0.8))
                }
            }.padding(.horizontal, 12).padding(.vertical, 8).background(Color(hex: "#0A0A0F").opacity(0.5))
            
            ScrollViewReader { proxy in
                ScrollView(.vertical, showsIndicators: true) {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(logs) { entry in
                            LogRow(entry: entry).id(entry.id)
                        }
                    }.padding(.horizontal, 12).padding(.vertical, 8)
                }.background(Color(hex: "#0A0A0F"))
                .onChange(of: logs.count) { newValue in
                    if autoScroll, let last = logs.last {
                        withAnimation(.easeOut(duration: 0.1)) { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
            }
        }
        .frame(height: 180)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color(hex: "#0A0A0F")).overlay(RoundedRectangle(cornerRadius: 12).stroke(Color(hex: "#1E293B"), lineWidth: 1)))
        .onAppear {
            addLog(level: .info, message: "Lum1na Beta 1 initialized")
            addLog(level: .info, message: "Device: iPhone15,2 (iOS 26.0)")
            addLog(level: .success, message: "Exploit chain loaded successfully")
            addLog(level: .debug, message: "Waiting for user action...")
        }
    }
    
    func addLog(level: LogLevel, message: String) {
        let entry = LogEntry(timestamp: Date(), level: level, message: message)
        logs.append(entry)
        if logs.count > 100 { logs.removeFirst(logs.count - 100) }
    }
}

struct LogRow: View {
    let entry: LogEntry
    
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(entry.formattedTimestamp).font(.system(.caption2, design: .monospaced)).foregroundStyle(Color(hex: "#64748B")).frame(width: 70, alignment: .leading)
            Text(entry.level.rawValue).font(.system(.caption2, design: .monospaced)).foregroundStyle(entry.level.color).frame(width: 24, alignment: .leading)
            Text(entry.message).font(.system(.caption2, design: .monospaced)).foregroundStyle(Color(hex: "#E2E8F0")).lineLimit(nil).fixedSize(horizontal: false, vertical: true)
            Spacer()
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

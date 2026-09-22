import SwiftUI

enum LogLevel: String {
    case info = "[*]"
    case success = "[+]"
    case warning = "[!]"
    case error = "[-]"
    case debug = "[#]"
    
    var color: Color {
        switch self {
        case .info:     return .consoleInfo
        case .success:  return .consoleSuccess
        case .warning:  return .consoleWarning
        case .error:    return .consoleError
        case .debug:    return .consoleTimestamp
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
                Text("console").font(.system(.caption, design: .monospaced)).foregroundStyle(.consoleTimestamp)
                Spacer()
                HStack(spacing: 8) {
                    Circle().fill(Color.consoleSuccess).frame(width: 6, height: 6)
                    Text("online").font(.system(.caption2, design: .monospaced)).foregroundStyle(.consoleSuccess.opacity(0.8))
                }
            }.padding(.horizontal, 12).padding(.vertical, 8).background(Color.consoleBackground.opacity(0.5))
            
            ScrollViewReader { proxy in
                ScrollView(.vertical, showsIndicators: true) {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(logs) { entry in
                            LogRow(entry: entry).id(entry.id)
                        }
                    }.padding(.horizontal, 12).padding(.vertical, 8)
                }.background(Color.consoleBackground)
                .onChange(of: logs.count) { _, _ in
                    if autoScroll, let last = logs.last {
                        withAnimation(.easeOut(duration: 0.1)) { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
            }
        }
        .frame(height: LayoutConstants.consoleHeight)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.consoleBackground).overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.circuitLine, lineWidth: 1)))
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
            Text(entry.formattedTimestamp).font(.consoleSmall).foregroundStyle(.consoleTimestamp).frame(width: 70, alignment: .leading)
            Text(entry.level.rawValue).font(.consoleSmall).foregroundStyle(entry.level.color).frame(width: 24, alignment: .leading)
            Text(entry.message).font(.consoleSmall).foregroundStyle(.consoleText).lineLimit(nil).fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
    }
}

class ConsoleViewModel: ObservableObject {
    @Published var logs: [LogEntry] = []
    
    func log(_ level: LogLevel, _ message: String) {
        let entry = LogEntry(timestamp: Date(), level: level, message: message)
        logs.append(entry)
        if logs.count > 500 { logs.removeFirst(logs.count - 500) }
    }
    
    func info(_ message: String) { log(.info, message) }
    func success(_ message: String) { log(.success, message) }
    func warning(_ message: String) { log(.warning, message) }
    func error(_ message: String) { log(.error, message) }
    func debug(_ message: String) { log(.debug, message) }
    func clear() { logs.removeAll() }
}

//
//  MatrixConsoleView.swift
//  Lum1na
//

import SwiftUI

enum CategorizedLogLevel: String, CaseIterable {
    case kernel = "[KERN]"
    case sandbox = "[SND]"
    case daemon = "[DAEM]"
    case patchset = "[PTCH]"
    case init_ = "[INIT]"
    case warning = "[WARN]"
    case error = "[ERR]"
    case success = "[OK]"

    var displayPrefix: String { rawValue }

    var color: Color {
        switch self {
        case .kernel:   return Color(hex: "#EF4444")
        case .sandbox:  return Color(hex: "#F59E0B")
        case .daemon:   return Color(hex: "#10B981")
        case .patchset: return Color(hex: "#3B82F6")
        case .init_:    return Color(hex: "#22D3EE")
        case .warning:  return Color(hex: "#FBBF24")
        case .error:    return Color(hex: "#F87171")
        case .success:  return Color(hex: "#4ADE80")
        }
    }
}

struct CategorizedLogEntry: Identifiable {
    let id = UUID()
    let timestamp: Date
    let level: CategorizedLogLevel
    let message: String

    var formattedTimestamp: String {
        LabTime.militaryNow(from: timestamp)
    }
}

@MainActor
class MatrixConsoleViewModel: ObservableObject {
    @Published var logs: [CategorizedLogEntry] = []
    @Published var autoScroll = true
    @Published var filterLevel: CategorizedLogLevel?

    var filteredLogs: [CategorizedLogEntry] {
        if let filter = filterLevel {
            return logs.filter { $0.level == filter }
        }
        return logs
    }

    func addLog(level: CategorizedLogLevel, message: String) {
        let entry = CategorizedLogEntry(timestamp: Date(), level: level, message: message)
        logs.append(entry)
        if logs.count > 1000 {
            logs.removeFirst(logs.count - 1000)
        }
    }

    func clear() {
        logs.removeAll()
    }
}

struct MatrixConsoleView: View {
    @StateObject private var viewModel = MatrixConsoleViewModel()
    @ObservedObject private var manager = ExploitManager.shared
    @State private var showFilters = false
    @State private var convertedCount = 0

    var body: some View {
        VStack(spacing: 0) {
            consoleHeader
            if showFilters { filterBar }
            logContent
        }
        .frame(height: 200)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(hex: "#0A0A0F"))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color(hex: "#1E293B"), lineWidth: 1)
                )
        )
        .onAppear {
            if viewModel.logs.isEmpty {
                viewModel.addLog(level: .init_, message: "Lum1na initialized")
                viewModel.addLog(level: .init_, message: "machine \(DeviceUtils.currentDeviceIdentifier)")
                viewModel.addLog(level: .init_, message: "osversion \(LabTime.sysctl("kern.osversion"))")
                viewModel.addLog(level: .init_, message: "chip \(DeviceUtils.currentChip)")
            }
        }
        .onReceive(manager.$lines) { lines in
            // Bridge ExploitManager output into the categorized console
            guard convertedCount < lines.count else { return }
            for line in lines[convertedCount...] {
                let (level, message) = Self.categorize(line)
                viewModel.addLog(level: level, message: message)
            }
            convertedCount = lines.count
        }
    }

    /// Maps ExploitManager ConsoleLine → categorized console entry
    private static func categorize(_ line: ConsoleLine) -> (CategorizedLogLevel, String) {
        switch line.level {
        case .success: return (.success, line.message)
        case .error:   return (.error, line.message)
        case .warning: return (.warning, line.message)
        case .info:
            let msg = line.message
            if msg.contains("KERNEL")   { return (.kernel, msg) }
            if msg.contains("SANDBOX")  { return (.sandbox, msg) }
            if msg.contains("DAEMON")   { return (.daemon, msg) }
            if msg.contains("PATCHSET") { return (.patchset, msg) }
            if msg.contains("===") || msg.contains("Stage:") { return (.init_, msg) }
            return (.init_, line.message)
        }
    }

    private var consoleHeader: some View {
        HStack(spacing: 12) {
            HStack(spacing: 6) {
                Image(systemName: "terminal.fill")
                    .font(.system(size: 10))
                    .foregroundStyle(Color(hex: "#64748B"))
                Text("console")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(Color(hex: "#64748B"))
            }

            Spacer()

            // Copy log to clipboard
            Button {
                UIPasteboard.general.string = viewModel.logs.map { entry in
                    "\(entry.formattedTimestamp) \(entry.level.displayPrefix) \(entry.message)"
                }.joined(separator: "\n")
            } label: {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 12))
                    .foregroundStyle(Color(hex: "#64748B"))
            }

            Button {
                withAnimation(.easeInOut(duration: 0.2)) { showFilters.toggle() }
            } label: {
                Image(systemName: "line.3.horizontal.decrease.circle")
                    .font(.system(size: 12))
                    .foregroundStyle(showFilters ? Color(hex: "#22D3EE") : Color(hex: "#64748B"))
            }

            HStack(spacing: 6) {
                Circle()
                    .fill(Color(hex: "#10B981"))
                    .frame(width: 6, height: 6)
                Text("online")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(Color(hex: "#10B981").opacity(0.8))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(hex: "#0F0F14"))
    }

    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(CategorizedLogLevel.allCases, id: \.self) { level in
                    FilterChip(
                        level: level,
                        isSelected: viewModel.filterLevel == level,
                        count: viewModel.logs.filter { $0.level == level }.count
                    ) {
                        if viewModel.filterLevel == level {
                            viewModel.filterLevel = nil
                        } else {
                            viewModel.filterLevel = level
                        }
                    }
                }

                Button { viewModel.clear() } label: {
                    Text("CLEAR")
                        .font(.system(.caption2, weight: .bold))
                        .foregroundStyle(Color(hex: "#64748B"))
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
        }
        .background(Color(hex: "#0A0A0F"))
    }

    private var logContent: some View {
        ScrollViewReader { proxy in
            ScrollView(.vertical, showsIndicators: true) {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(viewModel.filteredLogs) { entry in
                        CategorizedLogRow(entry: entry)
                            .id(entry.id)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
            }
            .background(Color(hex: "#0A0A0F"))
            .onChange(of: viewModel.filteredLogs.count) { _ in
                if viewModel.autoScroll, let last = viewModel.filteredLogs.last {
                    withAnimation(.easeOut(duration: 0.1)) {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
        }
    }

    func addLog(level: CategorizedLogLevel, message: String) {
        viewModel.addLog(level: level, message: message)
    }
}

struct FilterChip: View {
    let level: CategorizedLogLevel
    let isSelected: Bool
    let count: Int
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                Circle()
                    .fill(level.color)
                    .frame(width: 6, height: 6)
                Text(level.displayPrefix.replacingOccurrences(of: "[", with: "").replacingOccurrences(of: "]", with: ""))
                    .font(.system(.caption2, design: .monospaced, weight: isSelected ? .bold : .regular))
                if count > 0 {
                    Text("\(count)")
                        .font(.system(.caption2, design: .monospaced))
                }
            }
            .foregroundStyle(isSelected ? level.color : Color(hex: "#64748B"))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
                Capsule()
                    .fill(isSelected ? level.color.opacity(0.15) : Color(hex: "#1E293B").opacity(0.5))
            )
            .overlay(
                Capsule()
                    .stroke(isSelected ? level.color.opacity(0.5) : Color.clear, lineWidth: 1)
            )
        }
        .buttonStyle(PlainButtonStyle())
    }
}

struct CategorizedLogRow: View {
    let entry: CategorizedLogEntry

    var body: some View {
        HStack(alignment: .top, spacing: 6) {
            Text(entry.formattedTimestamp)
                .foregroundStyle(Color(hex: "#64748B"))
                .font(.system(.caption2, design: .monospaced))
                .frame(width: 148, alignment: .leading)

            Text(entry.level.displayPrefix)
                .font(.system(.caption2, design: .monospaced, weight: .bold))
                .foregroundStyle(entry.level.color)
                .frame(width: 45, alignment: .leading)

            Text(entry.message)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(Color(hex: "#E2E8F0"))
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)

            Spacer()
        }
        .padding(.vertical, 2)
    }
}

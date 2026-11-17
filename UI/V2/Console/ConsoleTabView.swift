//
//  ConsoleTabView.swift
//  Lum1na — CRT-only structured os_log-style stream + run log.
//

import SwiftUI

struct StructuredConsoleLine: Identifiable {
    enum OSLevel: String {
        case DEFAULT, INFO, DEBUG, ERROR, FAULT
        var tint: Color {
            switch self {
            case .DEFAULT: return Color.gray
            case .INFO: return Color(hex: "#60A5FA")
            case .DEBUG: return Color(hex: "#166534")
            case .ERROR: return LuminaV2Theme.danger
            case .FAULT: return Color(hex: "#D97706")
            }
        }
    }

    let id: UUID
    let time: String
    let level: OSLevel
    let process: String
    let subsystem: String
    let message: String
    let raw: ConsoleLine
}

enum StructuredConsole {
    static func map(_ line: ConsoleLine, pid: Int32, settings: LuminaV2Settings) -> StructuredConsoleLine {
        let msg = line.message.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = msg.lowercased()

        let level: StructuredConsoleLine.OSLevel = {
            switch line.level {
            case .error: return .ERROR
            case .warning:
                if lower.contains("fault") || lower.contains("watchdog") { return .FAULT }
                return .DEFAULT
            case .success: return .INFO
            case .info:
                if lower.contains("debug") || msg.hasPrefix("[*]") { return .DEBUG }
                return .DEFAULT
            }
        }()

        let process: String = {
            if lower.contains("[kern]") || lower.hasPrefix("kernel") || lower.contains("kernel[") {
                return "kernel[0]"
            }
            if lower.contains("syslog") {
                return "syslogd[1]"
            }
            return "lum1na[\(pid)]"
        }()

        let subsystem: String = {
            if process.hasPrefix("kernel") { return "kernel / mach" }
            if lower.contains("tap ") || lower.contains("probe") {
                return "com.lum1na.tests / probe"
            }
            if lower.contains("stage:") || lower.contains("[chain]") || lower.contains("full chain") {
                return "com.lum1na.chain / sequencer"
            }
            if lower.contains("board") || lower.contains("haskread") {
                return "com.lum1na.board / honesty"
            }
            return "com.lum1na.app / run"
        }()

        let time: String = {
            switch settings.timestampMode {
            case .off:
                return ""
            case .seconds, .milliseconds:
                let f = DateFormatter()
                f.locale = Locale(identifier: "en_US_POSIX")
                f.dateFormat = (settings.timestampMode == .milliseconds || settings.showMilliseconds)
                    ? "HH:mm:ss.SSS" : "HH:mm:ss"
                return f.string(from: line.timestamp)
            }
        }()

        let cleaned: String = {
            var m = msg
            for prefix in ["[*] ", "[+] ", "[!] ", "[-] ", "[KERN] "] {
                if m.hasPrefix(prefix) { m = String(m.dropFirst(prefix.count)); break }
            }
            return m
        }()

        return StructuredConsoleLine(
            id: line.id,
            time: time,
            level: level,
            process: process,
            subsystem: subsystem,
            message: cleaned,
            raw: line
        )
    }
}

struct ConsoleTabView: View {
    @Environment(LuminaAppStore.self) private var store
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var stickToBottom = true

    private var crt: Color { store.settings.crtTint.color }

    private var structured: [StructuredConsoleLine] {
        store.lines.map { StructuredConsole.map($0, pid: store.appPid, settings: store.settings) }
    }

    private var filtered: [StructuredConsoleLine] {
        structured.filter { line in
            if !store.consoleQuery.isEmpty {
                let q = store.consoleQuery.lowercased()
                let hay = (line.message + " " + line.process + " " + line.subsystem + " " + line.level.rawValue).lowercased()
                if !hay.contains(q) { return false }
            }
            switch store.consoleLevelFilter {
            case .all: return true
            case .lum1na: return line.process.lowercased().contains("lum1na")
            case .kernel: return line.process.lowercased().contains("kernel") || line.raw.message.uppercased().contains("[KERN]")
            case .subsystem: return line.subsystem.contains("com.lum1na") || line.subsystem.contains("kernel")
            case .error: return line.level == .ERROR || line.level == .FAULT
            }
        }
    }

    var body: some View {
        @Bindable var store = store
        ZStack {
            // CRT scanline wash (settings-controlled)
            if store.settings.crtScanlines {
                CRTScanlines(tint: crt)
                    .ignoresSafeArea()
                    .allowsHitTesting(false)
                    .opacity(0.35)
            }

            VStack(spacing: 12) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Console")
                            .font(.largeTitle.bold())
                            .foregroundStyle(crt)
                        HStack(spacing: 8) {
                            Text("LUM1NA")
                                .font(.caption.weight(.bold).monospaced())
                                .foregroundStyle(crt)
                            Circle().fill(store.isRunning || store.settings.liveStream ? crt : LuminaV2Theme.pending)
                                .frame(width: 7, height: 7)
                            Text(store.consolePaused ? "PAUSED" : "LIVE")
                                .font(.caption.weight(.semibold).monospaced())
                                .foregroundStyle(crt.opacity(0.85))
                        }
                    }
                    Spacer()
                    HStack(spacing: 8) {
                        iconButton(store.consolePaused ? "play.fill" : "pause.fill", label: store.consolePaused ? "Resume" : "Pause") {
                            store.consolePaused.toggle()
                            if !store.consolePaused { store.syncLinesFromManager() }
                        }
                        iconButton("doc.on.doc", label: "Copy console") {
                            store.copyToPasteboard(store.exportConsole())
                        }
                        iconButton("square.and.arrow.up", label: "Share console") {
                            store.share(store.exportConsole())
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)

                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(crt.opacity(0.7))
                    TextField("Search process, subsystem, message", text: $store.consoleQuery)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .foregroundStyle(crt)
                }
                .padding(12)
                .frame(minHeight: 44)
                .luminaCapsuleGlass(interactive: true)
                .overlay(
                    Capsule(style: .continuous)
                        .strokeBorder(crt.opacity(0.35), lineWidth: 1)
                )
                .padding(.horizontal, 16)

                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(LuminaAppStore.ConsoleLevelFilter.allCases) { filter in
                            let selected = store.consoleLevelFilter == filter
                            Button {
                                withAnimation(LuminaV2Theme.spring(reduceMotion: reduceMotion)) {
                                    store.consoleLevelFilter = filter
                                }
                            } label: {
                                Text(filter.rawValue)
                                    .font(.caption.weight(.semibold))
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 10)
                                    .frame(minHeight: 44)
                                    .background(
                                        Capsule().fill(selected ? crt.opacity(0.22) : Color.white.opacity(0.05))
                                    )
                                    .overlay(
                                        Capsule().strokeBorder(
                                            selected ? crt.opacity(0.7) : Color.white.opacity(0.1),
                                            lineWidth: 1
                                        )
                                    )
                                    .foregroundStyle(crt)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 16)
                }

                ZStack(alignment: .bottomTrailing) {
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 10) {
                                ForEach(filtered) { line in
                                    structuredRow(line)
                                        .id(line.id)
                                    Rectangle()
                                        .fill(crt.opacity(0.08))
                                        .frame(height: 1)
                                }
                                Color.clear.frame(height: 8).id("console-bottom")
                            }
                            .padding(16)
                        }
                        .background(
                            RoundedRectangle(cornerRadius: 16, style: .continuous)
                                .fill(Color.black.opacity(0.55))
                        )
                        .padding(.horizontal, 12)
                        .onChange(of: store.lines.count) { _, _ in
                            guard stickToBottom, !store.consolePaused, store.settings.liveStream else { return }
                            withAnimation(LuminaV2Theme.spring(reduceMotion: reduceMotion)) {
                                proxy.scrollTo("console-bottom", anchor: .bottom)
                            }
                        }

                        if !stickToBottom {
                            Button {
                                stickToBottom = true
                                proxy.scrollTo("console-bottom", anchor: .bottom)
                            } label: {
                                Label("Jump to latest", systemImage: "arrow.down")
                                    .font(.caption.weight(.semibold))
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 10)
                                    .frame(minHeight: 44)
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(LuminaV2Theme.accent)
                            .padding(16)
                        }
                    }
                    .simultaneousGesture(
                        DragGesture().onChanged { _ in stickToBottom = false }
                    )
                }
                .padding(.bottom, LuminaV2Theme.chipClearance)
            }
        }
    }

    private func iconButton(_ system: String, label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: system)
                .font(.body.weight(.semibold))
                .foregroundStyle(crt)
                .frame(width: 44, height: 44)
        }
        .buttonStyle(.plain)
        .luminaCapsuleGlass(interactive: true)
        .accessibilityLabel(label)
    }

    @ViewBuilder
    private func structuredRow(_ line: StructuredConsoleLine) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                if !line.time.isEmpty {
                    Text(line.time)
                        .font(.caption.monospaced())
                        .foregroundStyle(crt.opacity(0.85))
                }
                Text(line.level.rawValue)
                    .font(.caption2.weight(.bold).monospaced())
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(RoundedRectangle(cornerRadius: 4).fill(line.level.tint.opacity(0.35)))
                    .foregroundStyle(line.level == .DEBUG ? crt : .white)
                Text(line.process)
                    .font(.caption.weight(.semibold).monospaced())
                    .foregroundStyle(crt.opacity(0.9))
                Text(line.subsystem)
                    .font(.caption2.monospaced())
                    .foregroundStyle(crt.opacity(0.55))
                    .lineLimit(1)
            }
            Text(line.message)
                .font(.caption.monospaced())
                .foregroundStyle(messageColor(line))
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func messageColor(_ line: StructuredConsoleLine) -> Color {
        switch line.level {
        case .ERROR: return LuminaV2Theme.danger
        case .FAULT: return LuminaV2Theme.amber
        default: return crt.opacity(0.9)
        }
    }
}

private struct CRTScanlines: View {
    var tint: Color
    var body: some View {
        Canvas { context, size in
            let step: CGFloat = 3
            var y: CGFloat = 0
            while y < size.height {
                var path = Path()
                path.move(to: CGPoint(x: 0, y: y))
                path.addLine(to: CGPoint(x: size.width, y: y))
                context.stroke(path, with: .color(tint.opacity(0.06)), lineWidth: 1)
                y += step
            }
        }
    }
}

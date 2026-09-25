//
//  PersistentLogStore.swift
//  Lum1na
//
//  Crash-proof log using POSIX write + F_FULLFSYNC (the only
//  panic-surviving flush pattern, proven in P007 lab app).
//  No FileHandle: legacy FileHandle.write throws ObjC exceptions
//  that try? cannot catch. POSIX write returns -1 instead.
//

import Foundation

public final class PersistentLogStore {
    public static let shared = PersistentLogStore()

    public static let sessionStartMarker = "=== SESSION START"
    public static let sessionEndMarker = "=== SESSION END"

    private let fileURL: URL
    private let writeQueue = DispatchQueue(label: "lum1na.logstore", qos: .utility)

    private init() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        fileURL = docs.appendingPathComponent("lum1na_console.log")
        if !FileManager.default.fileExists(atPath: fileURL.path) {
            FileManager.default.createFile(atPath: fileURL.path, contents: nil)
        }
    }

    // MARK: Writing (POSIX, exception-free)

    private func writeSync(_ text: String, flush: Bool) {
        let fd = open(fileURL.path, O_CREAT | O_WRONLY | O_APPEND, 0o644)
        guard fd >= 0 else { return }
        defer { close(fd) }
        text.withCString { ptr in
            _ = write(fd, ptr, strlen(ptr))
        }
        if flush {
            fcntl(fd, F_FULLFSYNC)
        }
    }

    public func append(_ line: String) {
        writeQueue.async { [weak self] in
            self?.writeSync(line + "\n", flush: false)
        }
    }

    /// Synchronous append with a durable flush. Use for markers that
    /// MUST survive a panic: session start, tap markers, invoke lines.
    public func appendDurable(_ line: String) {
        writeQueue.sync {
            writeSync(line + "\n", flush: true)
        }
    }

    /// Tap marker: written BEFORE a controller runs. After a panic,
    /// marker present + no invoke line = the entry never executed.
    public func logTap(_ id: String) {
        appendDurable("TAP \(id) \(ISO8601DateFormatter().string(from: Date()))")
    }

    public func writeSessionStart() {
        appendDurable("\(PersistentLogStore.sessionStartMarker) \(ISO8601DateFormatter().string(from: Date())) ===")
        appendDurable("Device: \(DeviceUtils.currentDevice)")
        appendDurable("Chip: \(DeviceUtils.currentChip)")
    }

    public func markSessionEnd() {
        appendDurable("\(PersistentLogStore.sessionEndMarker) \(ISO8601DateFormatter().string(from: Date())) ===")
    }

    // MARK: Reading

    public func readAll() -> String? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// P007 pattern: extract only the LAST session from a log, so a
    /// recovered transcript shows the crash run, not the whole history.
    public func lastSession(_ full: String) -> String {
        let trimmed = full.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return trimmed }
        let lines = trimmed.components(separatedBy: "\n")
        var starts: [Int] = []
        for (i, line) in lines.enumerated() {
            let s = line.trimmingCharacters(in: .whitespaces)
            if s.hasPrefix("==="), s.lowercased().contains("session") {
                starts.append(i)
            }
        }
        guard let start = starts.last else { return trimmed }
        return lines[start...].joined(separator: "\n")
    }

    public func hasUncleanShutdown() -> Bool {
        guard let text = readAll() else { return false }
        guard let lastStart = text.range(of: PersistentLogStore.sessionStartMarker,
                                         options: .backwards) else {
            return false
        }
        let afterStart = text[lastStart.lowerBound...]
        return !afterStart.contains(PersistentLogStore.sessionEndMarker)
    }

    public func recoveryTranscript() -> String {
        guard let text = readAll() else { return "" }
        return lastSession(recoveryText(text))
    }

    private func recoveryText(_ text: String) -> String {
        guard let lastStart = text.range(of: PersistentLogStore.sessionStartMarker,
                                         options: .backwards) else {
            return text
        }
        return String(text[lastStart.lowerBound...])
    }

    public func clear() {
        writeQueue.async { [weak self] in
            guard let self = self else { return }
            try? Data().write(to: self.fileURL)
        }
    }
}

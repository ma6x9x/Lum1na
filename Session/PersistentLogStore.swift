//
//  PersistentLogStore.swift
//  Lum1na
//

import Foundation

/// Crash-proof console log.
/// Every line is appended to disk and flushed immediately, so the
/// transcript survives both app crashes and kernel panics.
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

    // MARK: Writing

    public func append(_ line: String) {
        writeQueue.async { [weak self] in
            guard let self = self,
                  let handle = try? FileHandle(forWritingTo: self.fileURL) else { return }
            defer { try? handle.close() }
            let data = Data((line + "\n").utf8)
            _ = try? handle.seekToEnd()
            handle.write(data)
            handle.synchronizeFile()
        }
    }

    public func writeSessionStart() {
        let stamp = ISO8601DateFormatter().string(from: Date())
        append("\(PersistentLogStore.sessionStartMarker) \(stamp) ===")
        append("Device: \(DeviceUtils.currentDevice)")
        append("Chip: \(DeviceUtils.currentChip)")
    }

    public func markSessionEnd() {
        append("\(PersistentLogStore.sessionEndMarker) \(ISO8601DateFormatter().string(from: Date())) ===")
    }

    // MARK: Reading

    /// True if the last session never wrote its END marker = crash/panic.
    public func hasUncleanShutdown() -> Bool {
        guard let text = readAll() else { return false }
        guard let lastStart = text.range(of: PersistentLogStore.sessionStartMarker,
                                         options: .backwards) else {
            return false
        }
        let afterStart = text[lastStart.lowerBound...]
        return !afterStart.contains(PersistentLogStore.sessionEndMarker)
    }

    /// The full transcript of the crashed session (from its START marker to EOF).
    public func recoveryTranscript() -> String {
        guard let text = readAll() else { return "" }
        guard let lastStart = text.range(of: PersistentLogStore.sessionStartMarker,
                                         options: .backwards) else {
            return text
        }
        return String(text[lastStart.lowerBound...])
    }

    public func readAll() -> String? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public func clear() {
        writeQueue.async { [weak self] in
            guard let self = self else { return }
            try? Data().write(to: self.fileURL)
        }
    }
}

//
//  AppOSLogBridge.swift
//  Lum1na — honest in-app OSLogStore reader (current process only).
//
//  Never fabricates other processes (kernel[0], syslogd[1], …).
//  OSLogStore(scope: .currentProcessIdentifier) is the public iOS 15+ path;
//  if it throws (entitlement / privacy), we surface an empty stream and keep
//  the run log — documented in UI/V2/README.md.
//

import Foundation
import OSLog

struct AppOSLogEntry: Identifiable, Equatable {
    let id: UUID
    let date: Date
    let level: StructuredConsoleLine.OSLevel
    let process: String
    let subsystem: String
    let category: String
    let message: String
    /// True only when the entry itself is kernel-tagged (subsystem/category/message), never invented.
    let isKernelTagged: Bool

    init(
        id: UUID = UUID(),
        date: Date,
        level: StructuredConsoleLine.OSLevel,
        process: String,
        subsystem: String,
        category: String,
        message: String,
        isKernelTagged: Bool
    ) {
        self.id = id
        self.date = date
        self.level = level
        self.process = process
        self.subsystem = subsystem
        self.category = category
        self.message = message
        self.isKernelTagged = isKernelTagged
    }
}

enum AppOSLogBridge {
    /// Executable label used in `process[pid]` rows.
    static var processLabel: String {
        let name = Bundle.main.object(forInfoDictionaryKey: "CFBundleExecutable") as? String
            ?? Bundle.main.executableURL?.lastPathComponent
            ?? "lum1na"
        return name.lowercased().contains("lum") ? "lum1na" : name
    }

    /// Pull recent entries for *this* process only. Returns [] on any failure.
    static func recent(minutes: Int = 10, limit: Int = 400, pid: Int32) -> [AppOSLogEntry] {
        do {
            let store = try OSLogStore(scope: .currentProcessIdentifier)
            let start = Date().addingTimeInterval(-Double(max(1, minutes)) * 60)
            let position = store.position(date: start)
            let sequence = try store.getEntries(at: position)
            var out: [AppOSLogEntry] = []
            out.reserveCapacity(min(limit, 128))
            for entry in sequence {
                if out.count >= limit { break }
                guard let log = entry as? OSLogEntryLog else { continue }
                let msg = log.composedMessage.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !msg.isEmpty else { continue }
                let subsystem = log.subsystem
                let category = log.category
                let tagged = Self.isKernelTagged(message: msg, subsystem: subsystem, category: category)
                let process = "\(processLabel)[\(pid)]"
                let subsystemLabel: String = {
                    if !subsystem.isEmpty && !category.isEmpty {
                        return "\(subsystem) / \(category)"
                    }
                    if !subsystem.isEmpty { return subsystem }
                    if !category.isEmpty { return category }
                    return "com.lum1na.app / oslog"
                }()
                // Stable id so polling refresh doesn't reshuffle ForEach identity.
                let seed = "\(log.date.timeIntervalSince1970)|\(process)|\(subsystem)|\(category)|\(msg)"
                let stableId = UUID(uuidString: uuidString(from: seed)) ?? UUID()
                out.append(
                    AppOSLogEntry(
                        id: stableId,
                        date: log.date,
                        level: mapLevel(log.level),
                        process: process,
                        subsystem: subsystemLabel,
                        category: category,
                        message: msg,
                        isKernelTagged: tagged
                    )
                )
            }
            return out
        } catch {
            // Entitlement / privacy / store unavailable — honest empty stream.
            return []
        }
    }

    static func isKernelTagged(message: String, subsystem: String, category: String) -> Bool {
        let blob = (message + " " + subsystem + " " + category).lowercased()
        if message.uppercased().contains("[KERN]") { return true }
        if subsystem.lowercased().contains("kernel") { return true }
        if category.lowercased().contains("kernel") { return true }
        if blob.contains("kern.") && (blob.contains("osversion") || blob.contains("bootargs")) {
            return true
        }
        return false
    }

    private static func mapLevel(_ level: OSLogEntryLog.Level) -> StructuredConsoleLine.OSLevel {
        switch level {
        case .debug: return .DEBUG
        case .info: return .INFO
        case .notice: return .DEFAULT
        case .error: return .ERROR
        case .fault: return .FAULT
        @unknown default: return .DEFAULT
        }
    }

    /// Deterministic UUID-shaped string from content (not cryptographic).
    private static func uuidString(from seed: String) -> String {
        var hash: UInt64 = 5381
        for b in seed.utf8 {
            hash = ((hash << 5) &+ hash) &+ UInt64(b)
        }
        var hash2: UInt64 = 0
        for b in seed.utf8.reversed() {
            hash2 = ((hash2 << 5) &+ hash2) &+ UInt64(b)
        }
        let a = UInt32(truncatingIfNeeded: hash)
        let b = UInt16(truncatingIfNeeded: hash >> 32)
        let c = UInt16(truncatingIfNeeded: hash >> 48)
        let d0 = UInt8(truncatingIfNeeded: hash2)
        let d1 = UInt8(truncatingIfNeeded: hash2 >> 8)
        let d2 = UInt8(truncatingIfNeeded: hash2 >> 16)
        let d3 = UInt8(truncatingIfNeeded: hash2 >> 24)
        let d4 = UInt8(truncatingIfNeeded: hash2 >> 32)
        let d5 = UInt8(truncatingIfNeeded: hash2 >> 40)
        let d6 = UInt8(truncatingIfNeeded: hash2 >> 48)
        let d7 = UInt8(truncatingIfNeeded: hash2 >> 56)
        return String(
            format: "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            a, b, c, d0, d1, d2, d3, d4, d5, d6, d7
        )
    }
}

//
//  PersistentLogStore.swift
//  Lum1na
//
//  P007-style crash-proof log: POSIX write + F_FULLFSYNC on every line
//  (the only panic-surviving flush pattern, proven in the lab app).
//  No FileHandle: FileHandle.write throws ObjC exceptions that try?
//  cannot catch. POSIX write returns -1 instead.
//
//  TAP markers go to p011_tap_log.txt BEFORE a controller runs, same
//  as P007. After a panic: marker present + no probe START = ObjC
//  entry never ran.
//

import Foundation

public final class PersistentLogStore {
    public static let shared = PersistentLogStore()

    public static let sessionStartMarker = "=== SESSION START"
    public static let sessionEndMarker = "=== SESSION END"
    public static let tapLogName = "p011_tap_log.txt"
    public static let consoleLogName = "lum1na_console.log"

    /// Catalog / stage id → Documents probe log. Keep in sync with
    /// filenames the ObjC probes already write; do not rename those files.
    public static let probeLogFiles: [String: String] = [
        "aks": consoleLogName,
        "p044": consoleLogName,
        "aio84530": consoleLogName,
        "ident": "device_ident_log.txt",
        "p010": "p010_queue_leak_log.txt",
        "p017v2": "p017_confused_deputy_log.txt",
        "p032": "p032_ane_open_log.txt",
        "p033": "p033_coreml_1in1out_log.txt",
        "p034": "p034_kmsg3072_occupancy_log.txt",
        "p040": "p040_ns_dest_log.txt",
        "p041": "p041_slide_dest_map_log.txt",
        "p042": "p042_reachability_log.txt",
        "p046": "p046_f77_patch_oracle_log.txt",
        "p050": "p050_getattrlist_oob_log.txt",
        "p051": "p051_apfs_xattr_log.txt",
        "p053": "p053_necp_dfree_log.txt",
        "p054": "p054_reap_list_log.txt",
        "p055": "p055_iosurface_upl_log.txt",
        "p009": "p009_pathb_log.txt",
        "p035": "p035_ave_wrap_log.txt",
        "p036": "p036_ave_paint_log.txt",
        "p037": "p037_ave_paint_log.txt",
        "p038": "p038_w_hunt_log.txt",
        "p043": "p043_write_class_map_log.txt",
        "p045": "p045_kmsg_recv_oracle_log.txt",
        "p052": "p052_nstream_extend_log.txt",
        "KERNEL": consoleLogName,
        "SANDBOX": consoleLogName,
        "DAEMON": consoleLogName,
        "PATCHSET": consoleLogName,
        "FULL CHAIN": consoleLogName,
        "Full Chain": consoleLogName
    ]

    private let docsURL: URL
    private let fileURL: URL
    private let tapURL: URL
    private let writeQueue = DispatchQueue(label: "lum1na.logstore", qos: .utility)

    private init() {
        docsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        fileURL = docsURL.appendingPathComponent(PersistentLogStore.consoleLogName)
        tapURL = docsURL.appendingPathComponent(PersistentLogStore.tapLogName)
        if !FileManager.default.fileExists(atPath: fileURL.path) {
            FileManager.default.createFile(atPath: fileURL.path, contents: nil)
        }
        if !FileManager.default.fileExists(atPath: tapURL.path) {
            FileManager.default.createFile(atPath: tapURL.path, contents: nil)
        }
    }

    // MARK: Writing (POSIX, exception-free, F_FULLFSYNC)

    private func writeSync(to url: URL, text: String, flush: Bool) {
        let fd = open(url.path, O_CREAT | O_WRONLY | O_APPEND, 0o644)
        guard fd >= 0 else { return }
        defer { close(fd) }
        text.withCString { ptr in
            _ = write(fd, ptr, strlen(ptr))
        }
        if flush {
            fcntl(fd, F_FULLFSYNC)
        }
    }

    /// Every console line is durable, matching P007 probe `p0xx_log` + F_FULLFSYNC.
    public func append(_ line: String) {
        writeQueue.sync {
            writeSync(to: fileURL, text: line + "\n", flush: true)
        }
    }

    /// Synchronous append with a durable flush. Same as `append` now;
    /// kept so existing call sites stay panic-safe.
    public func appendDurable(_ line: String) {
        append(line)
    }

    /// Tap marker: written BEFORE a controller runs. After a panic,
    /// marker present + no invoke/START line = the entry never executed.
    public func logTap(_ id: String) {
        let stamp = LabTime.militaryNow()
        let line = "TAP \(id) \(stamp)"
        writeQueue.sync {
            writeSync(to: tapURL, text: line + "\n", flush: true)
            writeSync(to: fileURL, text: line + "\n", flush: true)
        }
    }

    public func writeSessionStart() {
        let stamp = LabTime.militaryNow()
        let machine = LabTime.sysctl("hw.machine")
        let osversion = LabTime.sysctl("kern.osversion")
        let release = LabTime.unameRelease()
        let ident = [
            "\(PersistentLogStore.sessionStartMarker) \(stamp) ===",
            "machine        \(machine)",
            "osversion      \(osversion)",
            "release        \(release)",
            "chip           \(DeviceUtils.currentChip)",
            "category       \(DeviceUtils.deviceCategory)",
            "Runtime profile always wins."
        ].joined(separator: "\n")
        appendDurable(ident)
    }

    public func markSessionEnd() {
        appendDurable("\(PersistentLogStore.sessionEndMarker) \(LabTime.militaryNow()) ===")
    }

    // MARK: Reading

    public func readAll() -> String? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public func readTapLog() -> String? {
        guard let data = try? Data(contentsOf: tapURL) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Last *run* only. Do NOT split on `=== verdict` — that ate the full log
    /// in P007. Session headers look like `=== p051 session … ===`.
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

    public func lastTapId() -> String? {
        guard let tapRaw = readTapLog() else { return nil }
        for line in tapRaw.split(separator: "\n").reversed() {
            let parts = line.split(separator: " ")
            if parts.count >= 2, parts[0] == "TAP" {
                return String(parts[1])
            }
        }
        return nil
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

    /// Prefer the probe log for the last TAP, then fall back to the console
    /// last session, then newest mtime among Documents `*_log.txt`.
    public func recoveryTranscript() -> String {
        let tid = lastTapId()
        if let tid {
            let name = Self.probeLogFiles[tid] ?? Self.probeLogFiles[tid.lowercased()]
            if let name, let body = loadProbeLog(named: name) {
                return "=== RECOVERED (last TAP \(tid) → \(name)) ===\n"
                    + body
                    + "\n=== end ===\n"
            }
            if let name {
                return "=== RECOVERED ===\n"
                    + "Last TAP was \(tid), but \(name) is missing/empty "
                    + "(common after panic before F_FULLFSYNC).\n"
                    + "Check ips PC; re-run that probe after install.\n"
                    + fallbackConsoleSession()
                    + "\n=== end ===\n"
            }
        }

        if let newest = newestProbeLog() {
            var note = ""
            if let tid, let wanted = Self.probeLogFiles[tid], newest.name != wanted {
                note = "(NOTE: last TAP was \(tid) → wanted \(wanted); "
                    + "showing newest durable log instead.)\n"
            }
            return "=== RECOVERED (newest mtime: \(newest.name)) ===\n"
                + note
                + newest.body
                + "\n=== end ===\n"
        }

        let console = fallbackConsoleSession()
        if console.isEmpty { return "" }
        return "=== RECOVERED (console last session) ===\n"
            + console
            + "\n=== end ===\n"
    }

    private func loadProbeLog(named name: String) -> String? {
        let url = docsURL.appendingPathComponent(name)
        guard let raw = try? String(contentsOf: url, encoding: .utf8), !raw.isEmpty else {
            return nil
        }
        return lastSession(raw)
    }

    private func fallbackConsoleSession() -> String {
        guard let text = readAll(), !text.isEmpty else { return "" }
        return lastSession(text)
    }

    private func newestProbeLog() -> (name: String, body: String)? {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(
            at: docsURL,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) else { return nil }

        let skip: Set<String> = [Self.tapLogName]
        let mapped = Set(Self.probeLogFiles.values)
        var newest: (url: URL, date: Date)?
        for url in files {
            let name = url.lastPathComponent
            let looksLikeLog = name.hasSuffix("_log.txt") || name.hasSuffix("log.txt")
                || mapped.contains(name) || name == Self.consoleLogName
            guard looksLikeLog else { continue }
            guard !skip.contains(name) else { continue }
            let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))
                .flatMap(\.contentModificationDate) ?? .distantPast
            if newest == nil || date > newest!.date {
                newest = (url, date)
            }
        }
        guard let win = newest,
              let raw = try? String(contentsOf: win.url, encoding: .utf8),
              !raw.isEmpty else { return nil }
        return (win.url.lastPathComponent, lastSession(raw))
    }

    public func clear() {
        writeQueue.sync {
            try? Data().write(to: fileURL)
            try? Data().write(to: tapURL)
        }
    }
}

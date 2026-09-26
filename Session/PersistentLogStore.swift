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
        "aio84530": "p84530_aio_kqueue_log.txt",
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
        "cskrw": consoleLogName,
        "cscalib": "racecalib_log.txt",
        "luminakrw": "lumina_krw_log.txt",
        "apfs84523": "p052_nstream_extend_log.txt",
        "p057": "p057_wvek_log.txt",
        "p058": "p058_jpeg_log.txt",
        "p061": "p061_enctype_log.txt",
        "p062": "p06x_P062_log.txt",
        "p063": "p06x_IOGPU64788_log.txt",
        "p064": "p06x_P064_log.txt",
        "p005": consoleLogName,
        "lockdownd": consoleLogName,
        "p056": "p056_vt_compression_log.txt",
        "board": "lum1na_board.json",
        "afterkread": consoleLogName,
        "KERNEL": consoleLogName,
        "SANDBOX": consoleLogName,
        "DAEMON": "p054_reap_list_log.txt",
        "PATCHSET": consoleLogName,
        "FULL CHAIN": consoleLogName,
        "Full Chain": consoleLogName,
        "Full": consoleLogName
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

    /// Last app session only. Split on `=== SESSION START`, never on a
    /// probe banner like `=== P044 Session … ===` (that ate panic logs).
    public func lastSession(_ full: String) -> String {
        lastSession(full, previous: false)
    }

    public func lastSession(_ full: String, previous: Bool) -> String {
        let trimmed = full.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return trimmed }
        let lines = trimmed.components(separatedBy: "\n")
        var starts: [Int] = []
        for (i, line) in lines.enumerated() {
            if line.hasPrefix(PersistentLogStore.sessionStartMarker) {
                starts.append(i)
            }
        }
        guard let last = starts.last else { return trimmed }
        if previous, starts.count >= 2 {
            let prev = starts[starts.count - 2]
            return lines[prev..<last].joined(separator: "\n")
        }
        return lines[last...].joined(separator: "\n")
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

    /// One pasteable packet: board + last console session + last TAP file +
    /// tap markers. Call **before** `writeSessionStart` after a panic so
    /// `lastSession` is still the crashed session. After a new SESSION START
    /// pass `previousSession: true`.
    public func captureRecoveryPacket(
        boardJSON: String,
        sku: String,
        unclean: Bool,
        previousSession: Bool = false
    ) -> String {
        let stamp = LabTime.militaryNow()
        let tapId = lastTapId() ?? "none"
        let console = readAll() ?? ""
        let last = lastSession(console, previous: previousSession)
        let tapLines = (readTapLog() ?? "")
            .components(separatedBy: "\n")
            .filter { !$0.isEmpty }
            .suffix(8)
            .joined(separator: "\n")

        var extra = ""
        let probeName = Self.probeLogFiles[tapId] ?? Self.probeLogFiles[tapId.lowercased()]
        if let name = probeName,
           name != Self.consoleLogName,
           name != "lum1na_board.json",
           let body = loadProbeLog(named: name),
           !body.isEmpty {
            extra = "\n=== LAST TAP FILE (\(tapId) → \(name)) ===\n\(body)\n"
        }

        return """
        === LUM1NA RECOVERY \(stamp) ===
        last TAP: \(tapId)
        unclean: \(unclean ? "YES" : "NO")
        sku: \(sku)

        === BOARD ===
        \(boardJSON)
        \(extra)
        === LAST SESSION (console) ===
        \(last.isEmpty ? "(empty)" : last)

        === TAP MARKERS (last 8) ===
        \(tapLines.isEmpty ? "(none)" : tapLines)
        === end ===
        """
    }

    /// Live rebuild. Prefer `ExploitManager.lastRecoveryTranscript` (cached
    /// at launch before SESSION START) so Copy does not pick this session.
    public func recoveryTranscript() -> String {
        captureRecoveryPacket(
            boardJSON: Lum1naBoard.shared().jsonDump(),
            sku: LabDeviceProfile.skuName() as String? ?? "?",
            unclean: false,
            previousSession: true
        )
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

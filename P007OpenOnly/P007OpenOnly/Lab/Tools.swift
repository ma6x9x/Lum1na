import Foundation
import UIKit
import Darwin
import MachO

// MARK: - Installed application census (LSApplicationWorkspace)

struct InstalledApp: Identifiable, Hashable {
    var id: String { bundleID }
    let bundleID: String
    let name: String
    let version: String
    let bundlePath: String
    let dataPath: String
    let isSystem: Bool
    let isPlaceholder: Bool

    var displayName: String { name.isEmpty ? bundleID : name }
}

enum AppCensus {
    typealias DefaultWorkspaceFn = @convention(c) () -> AnyObject?
    typealias AllAppsFn = @convention(c) (AnyObject, Selector) -> AnyObject?

    /// LSApplicationWorkspace is private; call it through the ObjC runtime so nothing
    /// has to be linked at build time.
    static func installed() -> [InstalledApp] {
        guard let cls = NSClassFromString("LSApplicationWorkspace") as? NSObject.Type else { return [] }
        let sel = NSSelectorFromString("defaultWorkspace")
        guard cls.responds(to: sel) else { return [] }
        let workspace = cls.perform(sel)?.takeUnretainedValue()
        guard let ws = workspace else { return [] }

        let allSel = NSSelectorFromString("allInstalledApplications")
        guard ws.responds(to: allSel), let proxy = ws.perform(allSel)?.takeUnretainedValue() else { return [] }
        let array = proxy as? [AnyObject] ?? []

        var out: [InstalledApp] = []
        for item in array {
            let obj = item as AnyObject
            func str(_ name: String) -> String {
                let s = NSSelectorFromString(name)
                guard obj.responds(to: s) else { return "" }
                return (obj.perform(s)?.takeUnretainedValue() as? String) ?? ""
            }
            func url(_ name: String) -> String {
                let s = NSSelectorFromString(name)
                guard obj.responds(to: s) else { return "" }
                return ((obj.perform(s)?.takeUnretainedValue()) as? NSURL)?.path ?? ""
            }
            let bid = str("bundleIdentifier")
            guard !bid.isEmpty else { continue }
            out.append(InstalledApp(
                bundleID: bid,
                name: str("localizedName"),
                version: str("shortVersionString"),
                bundlePath: url("bundleURL"),
                dataPath: url("dataContainerURL"),
                isSystem: str("applicationType").contains("System"),
                isPlaceholder: str("applicationType").contains("Placeholder")))
        }
        return out.sorted { $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending }
    }

    /// Read an app's Info.plist even when its bundle path is unreadable, by asking the
    /// installation machinery for the metadata dictionary instead of the file.
    static func metadata(for bundleID: String) -> [String: Any] {
        guard let cls = NSClassFromString("LSApplicationProxy") as? NSObject.Type else { return [:] }
        let sel = NSSelectorFromString("applicationProxyForIdentifier:")
        guard cls.responds(to: sel) else { return [:] }
        guard let proxy = cls.perform(sel, with: bundleID)?.takeUnretainedValue() else { return [:] }
        let obj = proxy as AnyObject
        let dictSel = NSSelectorFromString("entitlements")
        var out: [String: Any] = [:]
        if obj.responds(to: dictSel) {
            out["entitlements"] = obj.perform(dictSel)?.takeUnretainedValue()
        }
        let groupSel = NSSelectorFromString("groupContainerURLs")
        if obj.responds(to: groupSel) {
            out["groupContainers"] = obj.perform(groupSel)?.takeUnretainedValue()
        }
        return out
    }
}

// MARK: - Process list (sysctl + libproc fallbacks, v2)
//
// The stock app sandbox denies sysctl(KERN_PROC, ALL) on current builds
// (EPERM before the kernel node runs), so v2 no longer swallows that:
// it records what happened, falls back to libproc (proc_listpids via
// dlsym — no header dependency), and resolves each pid's path with
// proc_pidpath (also dlsym'd). Pids whose path cannot be resolved still
// appear with the kinfo/comm name. Deputy pids (the LaunchDaemon-backed
// ANE/ML family in docs/DAEMONS_17_24A435.md) are flagged — they feed
// the P109 pid-borrow oracle; the flag is a name heuristic only, the
// kernel's kr decides entitlement truth.

struct ProcInfo: Identifiable, Hashable {
    var id: Int32 { pid }
    let pid: Int32
    let ppid: Int32
    let uid: UInt32
    let name: String
    let path: String
    let deputy: Bool
    let source: String   // "sysctl" / "libproc"
}

enum ProcList {
    static private(set) var status = ""

    /// The pid-borrow candidate families (LaunchDaemon-backed, 24A435 dump).
    static let deputyNames: [String] = [
        "aned", "nesessionmanager", "mlruntimed", "mlhostd", "modelmanagerd",
        "modelcatalogd", "siriinferenced", "siriknowledged", "corespeechd",
        "photoanalysisd", "mediaanalysisd", "generativeexperiencesd",
        "intelligenceplatformd", "intelligenceflowd", "visualintelligenced",
        "videocodecd", "mobilegestalt", "sirittsd", "speechmodeltrainingd",
        "assistantd", "sensingpredictd", "intelligencetasksd", "centaurid",
    ]

    static func snapshot() -> [ProcInfo] {
        var out = viaSysctl()
        if !out.isEmpty {
            status = "sysctl ok (\(out.count) pids)"
            return out
        }
        let lib = viaLibproc()
        if !lib.isEmpty {
            status = "sysctl denied → libproc ok (\(lib.count) pids)"
            return lib
        }
        status = "sysctl denied (errno \(errno)) and libproc empty — enumeration blocked, use pasteboard p151_pid or a deputy name"
        return []
    }

    private static func viaSysctl() -> [ProcInfo] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else {
            status = "sysctl size probe failed errno=\(errno)"
            return []
        }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 4, &buffer, &size, nil, 0) == 0 else {
            status = "sysctl read failed errno=\(errno)"
            return []
        }
        let count = size / MemoryLayout<kinfo_proc>.stride
        return buffer.withUnsafeBytes { raw -> [ProcInfo] in
            guard let base = raw.baseAddress else { return [] }
            var out: [ProcInfo] = []
            for i in 0..<count {
                let kp = base.advanced(by: i * MemoryLayout<kinfo_proc>.stride)
                    .assumingMemoryBound(to: kinfo_proc.self).pointee
                let pid = kp.kp_proc.p_pid
                if pid <= 0 { continue }
                let name = withUnsafeBytes(of: kp.kp_proc.p_comm) { buf -> String in
                    let bytes = buf.prefix(while: { $0 != 0 })
                    return String(decoding: bytes, as: UTF8.self)
                }
                out.append(ProcInfo(pid: pid,
                                    ppid: kp.kp_eproc.e_ppid,
                                    uid: kp.kp_eproc.e_ucred.cr_uid,
                                    name: name,
                                    path: "",
                                    deputy: isDeputy(name),
                                    source: "sysctl"))
            }
            return out.sorted { $0.pid < $1.pid }
        }
    }

    private static func viaLibproc() -> [ProcInfo] {
        typealias listpidsFn = @convention(c) (UInt32, UInt32, UnsafeMutableRawPointer?, Int32) -> Int32
        typealias pidpathFn = @convention(c) (Int32, UnsafeMutableRawPointer?, UInt32) -> Int32
        guard let h = dlopen(nil, RTLD_LAZY) else { return [] }
        guard let lp = dlsym(h, "proc_listpids") else { return [] }
        guard let pp = dlsym(h, "proc_pidpath") else { return [] }
        let listpids = unsafeBitCast(lp, to: listpidsFn.self)
        let pidpath = unsafeBitCast(pp, to: pidpathFn.self)
        let PROC_ALL_PIDS: UInt32 = 1
        let PROC_INFO_ALL: UInt32 = 0
        var size = listpids(PROC_ALL_PIDS, PROC_INFO_ALL, nil, 0)
        if size <= 0 {
            status = "libproc size probe failed errno=\(errno)"
            return []
        }
        var buf = [Int32](repeating: 0, count: Int(size) / 4 + 1)
        let got = listpids(PROC_ALL_PIDS, PROC_INFO_ALL, &buf, Int32(buf.count * 4))
        if got <= 0 {
            status = "libproc list failed errno=\(errno)"
            return []
        }
        var out: [ProcInfo] = []
        for i in 0..<(got / 4) {
            let pid = buf[i]
            if pid <= 0 { continue }
            var pathBuf = [CChar](repeating: 0, count: 4096)
            let n = pidpath(pid, &pathBuf, 4096)
            var path = ""
            if n > 0 {
                path = String(cString: pathBuf)
            }
            let name = path.isEmpty ? "" : (path as NSString).lastPathComponent
            out.append(ProcInfo(pid: pid,
                                ppid: 0,
                                uid: 0,   // libproc path doesn't carry uid; pane shows —
                                name: name.isEmpty ? "(\(pid))" : name,
                                path: path,
                                deputy: isDeputy(name),
                                source: "libproc"))
        }
        return out.sorted { $0.pid < $1.pid }
    }

    private static func isDeputy(_ name: String) -> Bool {
        let n = name.lowercased()
        return deputyNames.contains { n.contains($0) }
    }

    /// Write the census to Documents/p109_pid_census.txt for the P109 build.
    static func exportCensus(_ procs: [ProcInfo]) -> String? {
        guard !procs.isEmpty else { return nil }
        let dirs = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)
        guard let docs = dirs.first else { return nil }
        var text = "# pid census (\(procs.count) pids, \(procs.first?.source ?? "?"))" +
                   " — deputy rows feed the P109 Stage-B request (+0x180). kr oracle decides.\n"
        for p in procs {
            let mark = p.deputy ? " *" : ""
            let path = p.path.isEmpty ? "-" : p.path
            text += "\(p.pid)\t\(p.uid)\t\(p.name)\t\(path)\(mark)\n"
        }
        let url = URL(fileURLWithPath: docs).appendingPathComponent("p109_pid_census.txt")
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            return url.path
        } catch { return nil }
    }
}

// MARK: - Launch services / daemon census

enum LaunchCensus {
    struct Daemon: Identifiable {
        var id: String { path }
        let path: String
        let label: String
        let program: String
        let args: [String]
        let runAtLoad: Bool
        let keepAlive: Bool
        let keepAliveDict: Bool
        let envVars: Int
    }

    static func daemons() -> [Daemon] {
        let dirs = ["/System/Library/LaunchDaemons", "/System/Library/LaunchAgents",
                    "/Library/LaunchDaemons", "/private/var/jb/Library/LaunchDaemons"]
        var out: [Daemon] = []
        for dir in dirs {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for name in names where name.hasSuffix(".plist") {
                let path = (dir as NSString).appendingPathComponent(name)
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                    continue
                }
                let args = obj["ProgramArguments"] as? [String] ?? []
                let keep = obj["KeepAlive"]
                let env = obj["EnvironmentVariables"] as? [String: Any]
                out.append(Daemon(path: path,
                                  label: obj["Label"] as? String ?? name,
                                  program: obj["Program"] as? String ?? args.first ?? "",
                                  args: args,
                                  runAtLoad: (obj["RunAtLoad"] as? Bool) ?? false,
                                  keepAlive: (keep as? Bool) ?? false,
                                  keepAliveDict: keep is [String: Any],
                                  envVars: env?.count ?? 0))
            }
        }
        return out
    }

    /// Write label/program/args/policy per daemon to Documents/launchd_detail.txt —
    /// the program paths feed the binary inspector (daemon entitlement map).
    static func exportDetail(_ daemons: [Daemon]) -> String? {
        guard !daemons.isEmpty else { return nil }
        let dirs = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)
        guard let docs = dirs.first else { return nil }
        var text = "# launchd detail (\(daemons.count) plists) \u{2014} program paths feed the binary inspector\n"
        for d in daemons.sorted(by: { $0.label.caseInsensitiveCompare($1.label) == .orderedAscending }) {
            text += "[\(d.label)]\n\(d.path)\n"
            if !d.program.isEmpty { text += "  program: \(d.program)\n" }
            if !d.args.isEmpty { text += "  args: \(d.args.joined(separator: " "))\n" }
            if d.keepAlive { text += "  keepAlive: true\n" }
            if d.keepAliveDict { text += "  keepAlive: {conditional}\n" }
            if d.envVars > 0 { text += "  env: \(d.envVars) var(s)\n" }
            text += "\n"
        }
        let url = URL(fileURLWithPath: docs).appendingPathComponent("launchd_detail.txt")
        do { try text.write(to: url, atomically: true, encoding: .utf8); return url.path }
        catch { return nil }
    }
}

// MARK: - Keychain / identity surface

enum Identity {
    static func summary() -> [(String, String)] {
        var rows: [(String, String)] = []
        rows.append((tl("UDID (设备)"), sysctlString("kern.uuid") ?? "—"))
        rows.append((tl("机型"), sysctlString("hw.machine") ?? "—"))
        rows.append((tl("硬件型号"), sysctlString("hw.model") ?? "—"))
        rows.append((tl("序列号可读"), tl("否（需 IOKit 平台 Expert 接口）")))
        rows.append((tl("主机名"), sysctlString("kern.hostname") ?? "—"))
        rows.append((tl("启动 UUID"), sysctlString("kern.bootsessionuuid") ?? "—"))
        rows.append((tl("启动时间"), sysctlString("kern.boottime") ?? "—"))
        rows.append((tl("市场名称"), DeviceModel.current().marketingName))
        rows.append((tl("广告标识符"), ASIdentifierSummary.current))
        return rows
    }
}

enum ASIdentifierSummary {
    static var current: String {
        // ASIdentifierManager is in AdSupport; read through the runtime so nothing is linked.
        guard let cls = NSClassFromString("ASIdentifierManager") as? NSObject.Type else { return tl("不可用") }
        let sel = NSSelectorFromString("sharedManager")
        guard cls.responds(to: sel), let mgr = cls.perform(sel)?.takeUnretainedValue() else { return tl("不可用") }
        let uuidSel = NSSelectorFromString("advertisingIdentifier")
        guard (mgr as AnyObject).responds(to: uuidSel),
              let uuid = (mgr as AnyObject).perform(uuidSel)?.takeUnretainedValue() else { return tl("不可用") }
        return "\(uuid)"
    }
}

// MARK: - Crash log reader

struct CrashReport: Identifiable {
    var id: String { path }
    let path: String
    let name: String
    let date: Date?
    let process: String
    let exception: String
    let faultingSymbol: String
    let frames: [String]
    let size: Int
}

enum CrashLogs {
    static func searchPaths() -> [String] {
        var paths: [String] = []
        let home = NSHomeDirectory()
        paths.append(home + "/Library/Logs/DiagnosticReports")
        paths.append(home + "/Library/Logs/CrashReporter")
        paths.append("/private/var/mobile/Library/Logs/CrashReporter")
        paths.append("/private/var/mobile/Library/Logs/DiagnosticReports")
        return paths
    }

    static func list() -> [CrashReport] {
        let fm = FileManager.default
        var out: [CrashReport] = []
        for dir in searchPaths() {
            guard let names = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for name in names where name.hasSuffix(".ips") || name.hasSuffix(".crash") {
                let path = (dir as NSString).appendingPathComponent(name)
                guard let attrs = try? fm.attributesOfItem(atPath: path) else { continue }
                let size = (attrs[.size] as? NSNumber)?.intValue ?? 0
                let date = attrs[.modificationDate] as? Date
                var process = ""
                var exception = ""
                var fault = ""
                var frames: [String] = []
                if let data = try? Data(contentsOf: URL(fileURLWithPath: path)), data.count < 8_000_000 {
                    if let parsed = parse(data) {
                        process = parsed.process
                        exception = parsed.exception
                        fault = parsed.fault
                        frames = parsed.frames
                    }
                }
                out.append(CrashReport(path: path, name: name, date: date, process: process,
                                       exception: exception, faultingSymbol: fault,
                                       frames: frames, size: size))
            }
        }
        return out.sorted { ($0.date ?? .distantPast) > ($1.date ?? .distantPast) }
    }

    /// Write the crash index (path / process / exception) to Documents/crash_index.txt —
    /// each path line is a p116_dump_path.txt candidate for a full on-device .ips pull.
    static func exportIndex(_ reports: [CrashReport]) -> String? {
        guard !reports.isEmpty else { return nil }
        let dirs = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)
        guard let docs = dirs.first else { return nil }
        var text = "# crash index (\(reports.count) reachable reports) \u{2014} paths are p116_dump_path.txt candidates\n"
        for r in reports {
            let exc = r.exception.isEmpty ? "-" : r.exception
            let proc = r.process.isEmpty ? r.name : r.process
            text += "\(r.path)\n  \(proc) | \(exc) | \(r.size) B\n"
        }
        let url = URL(fileURLWithPath: docs).appendingPathComponent("crash_index.txt")
        do { try text.write(to: url, atomically: true, encoding: .utf8); return url.path }
        catch { return nil }
    }

    private static func parse(_ data: Data) -> (process: String, exception: String, fault: String, frames: [String])? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let parts = text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let bodyData = parts[1].data(using: .utf8),
              let body = try? JSONSerialization.jsonObject(with: bodyData) as? [String: Any] else {
            // legacy .crash text format
            let lines = text.split(separator: "\n").map(String.init)
            let proc = lines.first ?? ""
            let exc = lines.first(where: { $0.contains("Exception Type") }) ?? ""
            return (proc, exc, "", [])
        }
        let process = (body["procName"] as? String) ?? ""
        var exception = ""
        if let e = body["exception"] as? [String: Any] {
            let type = e["type"] as? String ?? ""
            let sub = e["subtype"] as? String ?? ""
            exception = sub.isEmpty ? type : "\(type) — \(sub)"
        }
        var frames: [String] = []
        var fault = ""
        let images = body["usedImages"] as? [[String: Any]] ?? []
        if let threads = body["threads"] as? [[String: Any]],
           let idx = body["faultingThread"] as? Int, idx < threads.count {
            let thread = threads[idx]
            if let fs = thread["frames"] as? [[String: Any]] {
                for f in fs.prefix(14) {
                    let imageIdx = f["imageIndex"] as? Int ?? 0
                    let image = imageIdx < images.count ? (images[imageIdx]["name"] as? String ?? "?") : "?"
                    let symbol = f["symbol"] as? String ?? ""
                    frames.append(symbol.isEmpty ? image : "\(image) · \(symbol)")
                }
                fault = frames.first ?? ""
            }
        }
        return (process, exception, fault, frames)
    }
}

// MARK: - Unified log reader

struct LogLine: Identifiable {
    var id = UUID()
    let time: Date
    let process: String
    let subsystem: String
    let message: String
}

enum UnifiedLog {
    /// OSLogStore is private-ish but reachable from an app for its own process scope.
    static func recent(minutes: Int = 5, limit: Int = 300) -> [LogLine] {
        guard let cls = NSClassFromString("OSLogStore") as? NSObject.Type else { return [] }
        let localSel = NSSelectorFromString("localStoreAndReturnError:")
        guard cls.responds(to: localSel) else { return [] }
        let store = cls.perform(localSel, with: nil)?.takeUnretainedValue()
        guard let storeObj = store as AnyObject? else { return [] }

        let posSel = NSSelectorFromString("positionWithDate:")
        guard storeObj.responds(to: posSel),
              let pos = storeObj.perform(posSel, with: Date().addingTimeInterval(-Double(minutes) * 60))?
                .takeUnretainedValue() else { return [] }

        let entriesSel = NSSelectorFromString("entriesFromPosition:to:options:error:")
        guard storeObj.responds(to: entriesSel) else { return [] }
        // Build the invocation-free path: entriesFromPosition:to:options:error: needs four
        // args, which perform(_:with:) cannot express. Fall back to the one-arg variant.
        let simpleSel = NSSelectorFromString("entriesEnumeratorWithOptions:position:predicate:error:")
        guard storeObj.responds(to: simpleSel) else { return [] }

        var out: [LogLine] = []
        guard let enumerator = storeObj.perform(simpleSel, with: pos)?.takeUnretainedValue() as? NSEnumerator else {
            return []
        }
        while let entry = enumerator.nextObject() as AnyObject? {
            if out.count >= limit { break }
            let dateSel = NSSelectorFromString("date")
            let compSel = NSSelectorFromString("composedMessage")
            let procSel = NSSelectorFromString("processIdentifier")
            let date = (entry.responds(to: dateSel) ? entry.perform(dateSel)?.takeUnretainedValue() as? Date : nil) ?? Date()
            let message = (entry.responds(to: compSel) ? entry.perform(compSel)?.takeUnretainedValue() as? String : nil) ?? ""
            let pid = (entry.responds(to: procSel) ? entry.perform(procSel)?.takeUnretainedValue() as? Int32 : nil) ?? 0
            guard !message.isEmpty else { continue }
            out.append(LogLine(time: date, process: "\(pid)", subsystem: "", message: message))
        }
        return out
    }
}

// MARK: - Binary inspector

struct MachOInfo {
    var arch: String = "—"
    var fileType: String = "—"
    var platform: String = "—"
    var minOS: String = "—"
    var sdk: String = "—"
    var isEncrypted: Bool = false
    var cryptID: UInt32 = 0
    var linkedLibraries: [String] = []
    var rpaths: [String] = []
    var entitlements: [String] = []
    var isFat: Bool = false
}

enum MachOInspector {
    static func inspect(_ path: String) -> MachOInfo? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        // a Mach-O header needs at least the magic; anything shorter is not one. The
        // load below would read past the buffer (or hit a nil base on empty Data).
        guard data.count >= 4 else { return nil }
        var info = MachOInfo()

        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }
        let fatMagic: UInt32 = 0xCAFEBABE
        let fatMagic64: UInt32 = 0xCAFEBABF
        if magic == fatMagic || magic == fatMagic64 {
            info.isFat = true
            return info
        }

        guard let header = parseHeader(data) else { return nil }
        info.arch = header.arch
        info.fileType = header.fileType
        info.platform = header.platform
        info.minOS = header.minOS
        info.sdk = header.sdk
        info.isEncrypted = header.cryptID != 0
        info.cryptID = header.cryptID
        info.linkedLibraries = header.libraries
        info.rpaths = header.rpaths
        info.entitlements = entitlementKeys(data)
        return info
    }

    /// v2: extract the embedded entitlements plist from the code-signature blob.
    /// We scan for CSMAGIC_ENTITLEMENTS (0xfade7171) — the blob header is
    /// magic/length, the body is XML plist text. Keys only; values are the
    /// device's private data and are NOT reported.
    static func entitlementKeys(_ data: Data) -> [String] {
        guard data.count > 8 else { return [] }
        let magicLE: [UInt8] = [0x71, 0x71, 0xDE, 0xFA]   // 0xfade7171 little-endian
        let n = data.count
        return data.withUnsafeBytes { (raw: UnsafeRawBuffer) -> [String] in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return [] }
            for i in 0..<(n - 8) {
                if base[i] == magicLE[0] && base[i+1] == magicLE[1] &&
                   base[i+2] == magicLE[2] && base[i+3] == magicLE[3] {
                    let len = UInt32(base[i+4]) | (UInt32(base[i+5]) << 8) |
                              (UInt32(base[i+6]) << 16) | (UInt32(base[i+7]) << 24)
                    guard len > 8, Int(len) <= n - i else { continue }
                    let xml = data.subdata(in: (i + 8)..<(i + Int(len)))
                    guard let plist = try? PropertyListSerialization.propertyList(
                        from: xml, format: nil) as? [String: Any] else { continue }
                    return plist.keys.sorted()
                }
            }
            return []
        }
    }

    private struct Header {
        var arch = "—"
        var fileType = "—"
        var platform = "—"
        var minOS = "—"
        var sdk = "—"
        var cryptID: UInt32 = 0
        var libraries: [String] = []
        var rpaths: [String] = []
    }

    private static func parseHeader(_ data: Data) -> Header? {
        guard data.count > 32 else { return nil }
        var h = Header()
        let cputype = data.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self) }
        switch cputype {
        case 0x0100_000C: h.arch = "arm64"
        case 0x0100_0007: h.arch = "x86_64"
        case 0x0000_000C: h.arch = "armv7"
        default: h.arch = "0x" + String(cputype, radix: 16)
        }
        let filetype = data.withUnsafeBytes { $0.load(fromByteOffset: 12, as: UInt32.self) }
        switch filetype {
        case 2: h.fileType = "MH_EXECUTE"
        case 6: h.fileType = "MH_DYLIB"
        case 8: h.fileType = "MH_BUNDLE"
        case 1: h.fileType = "MH_OBJECT"
        default: h.fileType = "type \(filetype)"
        }

        let ncmds = data.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self) }
        var offset = 32
        for _ in 0..<min(Int(ncmds), 4096) {
            guard offset + 8 <= data.count else { break }
            let cmd = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
            let size = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 4, as: UInt32.self) }
            guard size >= 8, offset + Int(size) <= data.count else { break }

            switch cmd {
            case 0x32: // LC_BUILD_VERSION
                if offset + 16 <= data.count {
                    let platform = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 8, as: UInt32.self) }
                    let minos = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 12, as: UInt32.self) }
                    h.platform = platformName(platform)
                    h.minOS = versionString(minos)
                    if offset + 20 <= data.count {
                        let sdk = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 16, as: UInt32.self) }
                        h.sdk = versionString(sdk)
                    }
                }
            case 0x24: // LC_VERSION_MIN_IPHONEOS
                if offset + 12 <= data.count {
                    h.platform = "iOS"
                    let minos = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 8, as: UInt32.self) }
                    h.minOS = versionString(minos)
                }
            case 0x21C: // LC_ENCRYPTION_INFO_64
                if offset + 20 <= data.count {
                    h.cryptID = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 16, as: UInt32.self) }
                }
            case 0xC: // LC_LOAD_DYLIB
                if let s = string(in: data, at: offset + 24, limit: offset + Int(size)) {
                    h.libraries.append((s as NSString).lastPathComponent)
                }
            case 0x1C: // LC_RPATH
                if let s = string(in: data, at: offset + 12, limit: offset + Int(size)) {
                    h.rpaths.append(s)
                }
            default:
                break
            }
            offset += Int(size)
        }
        return h
    }

    private static func string(in data: Data, at offset: Int, limit: Int) -> String? {
        guard offset < data.count, offset < limit else { return nil }
        var bytes: [UInt8] = []
        var i = offset
        while i < min(limit, data.count), data[i] != 0 {
            bytes.append(data[i])
            i += 1
        }
        return bytes.isEmpty ? nil : String(decoding: bytes, as: UTF8.self)
    }

    private static func platformName(_ v: UInt32) -> String {
        switch v {
        case 1: return "macOS"
        case 2: return "iOS"
        case 3: return "tvOS"
        case 4: return "watchOS"
        case 6: return "Mac Catalyst"
        case 7: return "iOS Simulator"
        case 11: return "visionOS"
        default: return "platform \(v)"
        }
    }

    private static func versionString(_ v: UInt32) -> String {
        "\(v >> 16).\((v >> 8) & 0xff).\(v & 0xff)"
    }
}

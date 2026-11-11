import Foundation
import Combine
import Darwin

enum Reach: String, Codable, CaseIterable {
    case inProcess = "进程内"
    case systemProcess = "系统进程"
    case kernel = "内核"
    case entitlementGated = "权限受限"
    case radio = "无线链路"
    case peripheral = "外设"

    /// Localized display name; rawValue stays Chinese as the stable storage key.
    var label: String { tl(rawValue) }
}

enum PrimitiveKind: String, Codable, CaseIterable {
    case oobWrite = "OOB 写"
    case oobRead = "OOB 读"
    case uaf = "UAF"
    case infoLeak = "信息泄露"
    case typeConfusion = "类型混淆"
    case intOverflow = "整数溢出"
    case probe = "探测"

    /// Localized display name; rawValue stays Chinese as the stable storage key.
    var label: String { tl(rawValue) }
}

struct ModuleOutcome {
    var headline: String
    var detail: String = ""
    var evidence: [String] = []
    var artifacts: [URL] = []
    var elapsedMs: Int = 0
    /// Set only when the module threw. The headline is display text and may be localized,
    /// so it must never be compared against a literal to detect failure.
    var failed: Bool = false

    func copyBlock(moduleId: String) -> String {
        var lines = ["id=\(moduleId)", headline]
        if !detail.isEmpty { lines.append(detail) }
        lines.append(contentsOf: evidence)
        if elapsedMs > 0 { lines.append("elapsedMs=\(elapsedMs)") }
        if !artifacts.isEmpty {
            lines.append("--- artifacts ---")
            lines.append(contentsOf: artifacts.map(\.path))
        }
        return lines.joined(separator: "\n")
    }
}

/// Documents/lum1na/<id>_log.txt + Documents/lum1na_lab_log.txt. Full text for Copy.
enum LabLogStore {
    static var dir: URL {
        let u = Container.documents.appendingPathComponent("lum1na", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }
    static var labLog: URL {
        Container.documents.appendingPathComponent("lum1na_lab_log.txt")
    }

    static func safeId(_ id: String) -> String {
        id.replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: " ", with: "_")
    }

    static func url(for id: String) -> URL {
        dir.appendingPathComponent("\(safeId(id))_log.txt")
    }

    static func persist(id: String, title: String, cve: String,
                        outcome: ModuleOutcome, history: [JournalEntry]) -> URL {
        var lines: [String] = []
        lines.append("=== CINDER \(id) ===")
        lines.append("title=\(title)")
        lines.append("cve=\(cve)")
        lines.append("when=\(ISO8601DateFormatter().string(from: Date()))")
        lines.append(outcome.copyBlock(moduleId: id))
        if !history.isEmpty {
            lines.append("--- journal ---")
            for e in history {
                lines.append("\(e.phase)\t\(ISO8601DateFormatter().string(from: e.armedAt))\t\(e.detail)")
            }
        }
        let body = lines.joined(separator: "\n") + "\n\n"
        let dest = url(for: id)
        append(body, to: dest)
        append(body, to: labLog)
        return dest
    }

    static func readFull(id: String) -> String? {
        FileLoader.tail(at: url(for: id).path, maxBytes: 512_000)
    }

    static func copyAll() -> String {
        FileLoader.tail(at: labLog.path, maxBytes: 512_000) ?? "(no test runs yet)"
    }

    static func append(_ s: String, to url: URL) {
        guard let d = s.data(using: .utf8) else { return }
        let fd = open(url.path, O_CREAT | O_APPEND | O_WRONLY, 0o644)
        guard fd >= 0 else { return }
        d.withUnsafeBytes { raw in _ = write(fd, raw.baseAddress, raw.count) }
        fcntl(fd, F_FULLFSYNC)
        close(fd)
    }
}

final class RunContext {
    let workdir: URL
    let journal: GuardJournal

    init(workdir: URL, journal: GuardJournal) {
        self.workdir = workdir
        self.journal = journal
    }

    @discardableResult
    func write(_ name: String, _ data: Data) -> URL {
        let url = workdir.appendingPathComponent(name)
        try? data.write(to: url, options: .atomic)
        return url
    }

    func seed(_ name: String) -> Data? {
        let bundle = Bundle.main
        let urls: [URL?] = [
            bundle.url(forResource: name, withExtension: nil),
            bundle.url(forResource: name, withExtension: nil, subdirectory: "LabSeeds"),
            bundle.url(forResource: (name as NSString).deletingPathExtension,
                       withExtension: (name as NSString).pathExtension),
            bundle.url(forResource: (name as NSString).deletingPathExtension,
                       withExtension: (name as NSString).pathExtension,
                       subdirectory: "LabSeeds")
        ]
        for url in urls {
            if let url, let data = try? Data(contentsOf: url) { return data }
        }
        return nil
    }

    func arm(_ id: String, _ detail: String) { journal.arm(id, detail) }
    func disarm(_ id: String, _ detail: String = "") { journal.disarm(id, phase: "done", detail: detail) }
    func fail(_ id: String, _ detail: String) { journal.disarm(id, phase: "threw", detail: detail) }
}

struct ExploitModule: Identifiable {
    let id: String
    /// Chinese source text. English lives in ModuleText, keyed by `id`.
    let titleZh: String
    let cve: String
    let component: String
    let primitive: PrimitiveKind
    let reach: Reach
    /// 1 = primitive fired on a device before, 2 = fix site proven at instruction level,
    /// 3 = reachability probe / honest negative.
    let tier: Int
    let summaryZh: String
    let notesZh: String
    let run: (RunContext) throws -> ModuleOutcome

    var title: String { ModuleText.resolve(id, .title, zh: titleZh) }
    var summary: String { ModuleText.resolve(id, .summary, zh: summaryZh) }
    var notes: String { ModuleText.resolve(id, .notes, zh: notesZh) }
}

struct LabError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

final class LabEngine: ObservableObject {
    @Published private(set) var outcomes: [String: ModuleOutcome] = [:]
    @Published private(set) var running: Set<String> = []
    @Published private(set) var logLines: [String] = []

    let journal: GuardJournal
    let workdir: URL

    init() {
        // Create every standard directory before anything writes into it. This is the single
        // place that decides whether the container is usable.
        Container.ensureAll()
        journal = GuardJournal()
        workdir = Container.work
        try? FileManager.default.createDirectory(at: workdir, withIntermediateDirectories: true)
        LuminaLearn.ingestDeaths(journal.recovered)
        if !journal.recovered.isEmpty {
            let names = journal.recovered.map(\.moduleID).joined(separator: ",")
            log("learn: death-oracle recovered \(journal.recovered.count) armed-not-disarmed [\(names)]")
        }
    }

    func log(_ line: String) {
        let stamped = String(format: "[%02d:%02d:%02d] %@",
                             Calendar.current.component(.hour, from: Date()),
                             Calendar.current.component(.minute, from: Date()),
                             Calendar.current.component(.second, from: Date()),
                             line)
        DispatchQueue.main.async {
            self.logLines.append(stamped)
            if self.logLines.count > 400 { self.logLines.removeFirst(self.logLines.count - 400) }
        }
        LabLogStore.append(stamped + "\n", to: LabLogStore.labLog)
    }

    func copyAllResults() -> String {
        var parts = [LabLogStore.copyAll()]
        let ids = outcomes.keys.sorted()
        if !ids.isEmpty {
            parts.append("=== IN-MEMORY OUTCOMES \(ids.count) ===")
            for id in ids {
                if let o = outcomes[id] { parts.append(o.copyBlock(moduleId: id)); parts.append("") }
            }
        }
        return parts.joined(separator: "\n")
    }

    func run(_ module: ExploitModule) {
        guard !running.contains(module.id) else { return }
        running.insert(module.id)
        log("▸ \(module.id)")
        LuminaLearn.begin(module.id)
        LuminaLearn.prepare(module.id)

        let ctx = RunContext(workdir: workdir, journal: journal)
        let started = Date()

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                var out = try module.run(ctx)
                out.elapsedMs = Int(Date().timeIntervalSince(started) * 1000)
                let footer = LuminaLearn.finish(module.id, log: out.headline + "\n" + out.detail)
                let hist = ctx.journal.history(for: module.id)
                let logURL = LabLogStore.persist(id: module.id, title: module.title,
                                                    cve: module.cve, outcome: out, history: hist)
                DispatchQueue.main.async {
                    self.outcomes[module.id] = out
                    self.running.remove(module.id)
                    let head = String(out.headline.prefix(160))
                    self.log("✓ \(module.id) — \(head) (\(out.elapsedMs) ms)")
                    for line in footer.components(separatedBy: .newlines) where line.hasPrefix("hasKread") {
                        self.log("  " + String(line.prefix(160)))
                    }
                    _ = logURL
                }
            } catch {
                let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                ctx.fail(module.id, message)
                var out = ModuleOutcome(headline: tl("失败"), detail: message, failed: true)
                out.elapsedMs = Int(Date().timeIntervalSince(started) * 1000)
                _ = LuminaLearn.finish(module.id, log: "failed\n" + message)
                let hist = ctx.journal.history(for: module.id)
                _ = LabLogStore.persist(id: module.id, title: module.title,
                                           cve: module.cve, outcome: out, history: hist)
                DispatchQueue.main.async {
                    self.outcomes[module.id] = out
                    self.running.remove(module.id)
                    self.log("✗ \(module.id) — \(String(message.prefix(160)))")
                }
            }
        }
    }

    func outcome(for id: String) -> ModuleOutcome? { outcomes[id] }
}

extension LabEngine {
    /// Sequential run — used by the chain view, where stage N only means something after
    /// stage N-1 has produced its artifact.
    func runSequence(_ modules: [ExploitModule], label: String) {
        log("══ " + tl("序列开始: ") + "\(label)（\(modules.count) " + tl("个原语") + "）")
        // Kick the whole sequence off on main, then hand each stage to a background queue.
        // Never `main.sync` from the worker: that is a deadlock waiting for main to be busy
        // on something that needs the worker.
        runStage(modules, index: 0, label: label)
    }

    private func runStage(_ modules: [ExploitModule], index: Int, label: String) {
        guard index < modules.count else {
            log("══ " + tl("序列结束: ") + "\(label)")
            return
        }
        let module = modules[index]
        running.insert(module.id)
        LuminaLearn.begin(module.id)
        LuminaLearn.prepare(module.id)
        let ctx = RunContext(workdir: workdir, journal: journal)
        let started = Date()

        DispatchQueue.global(qos: .userInitiated).async {
            var out: ModuleOutcome
            do {
                out = try module.run(ctx)
                _ = LuminaLearn.finish(module.id, log: out.headline + "\n" + out.detail)
            } catch {
                let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                ctx.fail(module.id, message)
                out = ModuleOutcome(headline: tl("失败"), detail: message, failed: true)
                _ = LuminaLearn.finish(module.id, log: "failed\n" + message)
            }
            out.elapsedMs = Int(Date().timeIntervalSince(started) * 1000)
            let finished = out
            let hist = ctx.journal.history(for: module.id)
            _ = LabLogStore.persist(id: module.id, title: module.title,
                                       cve: module.cve, outcome: finished, history: hist)
            let next = index + 1
            DispatchQueue.main.async {
                self.outcomes[module.id] = finished
                self.running.remove(module.id)
                self.log(finished.failed
                         ? "  ✗ \(module.title) — \(finished.detail)"
                         : "  ✓ \(module.title) — \(finished.headline)")
                self.runStage(modules, index: next, label: label)
            }
        }
    }
}

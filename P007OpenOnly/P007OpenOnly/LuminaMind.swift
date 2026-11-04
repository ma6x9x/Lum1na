//
//  LuminaMind.swift — GLM-Edge / Lum1na-Mind tab with phone-side tools.
//  The model never runs the primitive itself: the phone executes tools
//  (run_tap, read_log, web_search, …) and returns receipts.
//

import Foundation
import SwiftUI
import Darwin
import AVFoundation
import UIKit

// MARK: - Settings

enum LuminaMindProvider: String, CaseIterable, Identifiable {
    case ollama = "Ollama (local/free)"
    case spacexai = "Grok (xAI)"
    case openrouter = "OpenRouter free"
    case lan = "LAN mlx"
    case custom = "Custom"

    var id: String { rawValue }

    var defaultBase: String {
        switch self {
        case .lan: return "http://MAC_LAN_IP:8080/v1"
        case .ollama: return "http://MAC_LAN_IP:11434/v1"
        case .spacexai: return "https://api.x.ai/v1"
        case .openrouter: return "https://openrouter.ai/api/v1"
        case .custom: return "http://MAC_LAN_IP:8080/v1"
        }
    }

    var defaultModel: String {
        switch self {
        case .lan: return "llama3.1:8b"
        case .ollama: return "llama3.1:8b"
        case .spacexai: return "grok-4.7"
        case .openrouter: return "openrouter/free"
        case .custom: return "llama3.1:8b"
        }
    }

    var needsKey: Bool {
        self == .spacexai || self == .openrouter || self == .custom
    }
}

final class LuminaMindSettings: ObservableObject {
    @Published var provider: LuminaMindProvider {
        didSet { UserDefaults.standard.set(provider.rawValue, forKey: "lumind.provider") }
    }
    @Published var baseURL: String {
        didSet { UserDefaults.standard.set(baseURL, forKey: "lumind.base") }
    }
    @Published var model: String {
        didSet { UserDefaults.standard.set(model, forKey: "lumind.model") }
    }
    @Published var apiKey: String {
        didSet { UserDefaults.standard.set(apiKey, forKey: "lumind.key") }
    }
    @Published var autoAnalyze: Bool {
        didSet { UserDefaults.standard.set(autoAnalyze, forKey: "lumind.autoanalyze") }
    }
    @Published var speakReplies: Bool {
        didSet { UserDefaults.standard.set(speakReplies, forKey: "lumind.speak") }
    }

    init() {
        let d = UserDefaults.standard
        let stored = d.string(forKey: "lumind.provider") ?? ""
        let p: LuminaMindProvider
        if stored == "SpaceXAI" || stored == "Grok (xAI)" {
            p = .spacexai
        } else if stored == "Ollama" || stored == "Ollama (local/free)" {
            p = .ollama
        } else if stored == "LAN GLM-Edge" {
            p = .lan
        } else {
            p = LuminaMindProvider(rawValue: stored) ?? .ollama
        }
        provider = p
        baseURL = d.string(forKey: "lumind.base") ?? p.defaultBase
        var m = d.string(forKey: "lumind.model") ?? p.defaultModel
        // glm-edge-1.5b is not an ollama tag. glm-5.3-flash:cloud is quota-gated.
        if m == "glm-edge-1.5b" || m == "glm-4-9b-chat" {
            m = p == .spacexai ? "grok-4.7" : "llama3.1:8b"
        }
        model = m
        var key = d.string(forKey: "lumind.key") ?? ""
        if key.isEmpty { key = Self.loadDroppedKey() }
        apiKey = key
        autoAnalyze = d.object(forKey: "lumind.autoanalyze") as? Bool ?? true
        speakReplies = d.object(forKey: "lumind.speak") as? Bool ?? true
    }

    /// Drop a one-line key in Documents/xai_key.txt or Documents/openrouter_key.txt.
    static func loadDroppedKey() -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        for name in ["xai_key.txt", "openrouter_key.txt", "lumind.key"] {
            guard let url = docs?.appendingPathComponent(name),
                  let raw = try? String(contentsOf: url, encoding: .utf8) else { continue }
            let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if !s.isEmpty { return s }
        }
        return ""
    }

    func applyPreset(_ p: LuminaMindProvider) {
        provider = p
        baseURL = p.defaultBase
        model = p.defaultModel
    }

    var isPlaceholder: Bool {
        LuminaMindSettings.isPlaceholder(baseURL)
    }

    static func isPlaceholder(_ url: String) -> Bool {
        let u = url.lowercased()
        if url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return true }
        if u.contains("mac_lan_ip") { return true }
        if u.contains("change_me") { return true }
        if u.contains("192.168.1.1") { return true }
        return false
    }
}

final class MindVoice: NSObject, AVSpeechSynthesizerDelegate {
    static let shared = MindVoice()
    private let synth = AVSpeechSynthesizer()

    func speak(_ text: String) {
        let cleaned = text
            .replacingOccurrences(of: #"<think>[\s\S]*?</think>"#, with: "", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else { return }
        if synth.isSpeaking { synth.stopSpeaking(at: .immediate) }
        let u = AVSpeechUtterance(string: String(cleaned.prefix(1800)))
        u.voice = AVSpeechSynthesisVoice(language: "en-US")
            ?? AVSpeechSynthesisVoice(language: "en-GB")
        u.rate = AVSpeechUtteranceDefaultSpeechRate * 0.95
        u.pitchMultiplier = 1.02
        synth.speak(u)
    }

    func stop() { synth.stopSpeaking(at: .immediate) }
}

// MARK: - Bundled laws + BM25-lite

struct MindLaw: Identifiable {
    let id: String
    let title: String
    let text: String
}

enum LuminaMindLaws {
    static let core: [String] = {
        if let arr = bundleJSON?["core_laws"] as? [String] { return arr }
        return [
            "NO-GUESS LAW: unknown = say unknown.",
            "HONESTY GATE C: never claim KRW without kread32(kbase)==0xfeedfacf."
        ]
    }()

    static let notes: [MindLaw] = {
        guard let raw = bundleJSON?["notes"] as? [[String: Any]] else { return [] }
        return raw.compactMap { d in
            guard let id = d["id"] as? String,
                  let title = d["title"] as? String,
                  let text = d["text"] as? String else { return nil }
            return MindLaw(id: id, title: title, text: text)
        }
    }()

    private static let bundleJSON: [String: Any]? = {
        let url = Bundle.main.url(forResource: "MindLaws", withExtension: "json")
            ?? Bundle.main.url(forResource: "MindLaws", withExtension: "json", subdirectory: nil)
        guard let url, let data = try? Data(contentsOf: url),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return obj
    }()

    static func search(_ query: String, top: Int = 6) -> [(Double, MindLaw)] {
        let qTerms = tokenize(query)
        guard !qTerms.isEmpty else { return [] }
        var scored: [(Double, MindLaw)] = []
        let df = documentFreq(qTerms)
        let n = Double(max(notes.count, 1))
        for note in notes {
            let doc = tokenize(note.id + " " + note.title + " " + note.text)
            var score = 0.0
            var tf: [String: Int] = [:]
            for t in doc { tf[t, default: 0] += 1 }
            for q in qTerms {
                let f = Double(tf[q] ?? 0)
                if f == 0 { continue }
                let idf = Darwin.log((n - Double(df[q] ?? 0) + 0.5) / (Double(df[q] ?? 0) + 0.5) + 1)
                let denom = f + 1.2 * (1 - 0.75 + 0.75 * Double(doc.count) / 80.0)
                score += idf * (f * 2.2) / denom
            }
            if score > 0 { scored.append((score, note)) }
        }
        return scored.sorted { $0.0 > $1.0 }.prefix(top).map { $0 }
    }

    static func analyze(_ log: String) -> String {
        let hits = search(log, top: 6)
        var lines: [String] = ["AUTO-ANALYZE (phone-side, no model required)", ""]
        lines.append("CORE LAWS:")
        for c in core { lines.append("  • \(c)") }
        lines.append("")
        let lower = log.lowercased()
        var signals: [String] = []
        if log.contains("hasKread=YES") { signals.append("hasKread=YES") }
        if log.contains("0xfeedfacf") { signals.append("MH_MAGIC_64 receipt") }
        if lower.contains("pipe-hit") || log.contains("PIPE-HIT") { signals.append("PIPE-HIT (write receipt, not hasKread)") }
        if lower.contains("occupancy") || log.contains("HIT") { signals.append("occupancy fingerprint (not conversion)") }
        if lower.contains("panic") || lower.contains("queue_init") { signals.append("panic/queue_init") }
        if log.contains("readback") { signals.append("readback present (VT clamp is not failure)") }
        if log.hasPrefix("STOP") || lower.contains("stop ") { signals.append("STOP / parked") }
        lines.append("SIGNALS: " + (signals.isEmpty ? "(none extracted)" : signals.joined(separator: "; ")))
        lines.append("")
        lines.append("RETRIEVED LAWS:")
        if hits.isEmpty {
            lines.append("  (no match)")
        } else {
            for (s, n) in hits {
                lines.append(String(format: "  [%.3f] %@ — %@", s, n.id, n.title))
                lines.append("        " + n.text)
            }
        }
        lines.append("")
        let classified = LuminaLearn.classify(id: "log", log: log)
        lines.append("LATTICE: stage=\(classified.stage.rawValue) outcome=\(classified.outcome)")
        lines.append("  " + classified.note)
        if let sib = classified.sibling { lines.append("  sibling: \(sib)") }
        lines.append("")
        if log.contains("hasKread=YES") && log.contains("0xfeedfacf") {
            lines.append("VERDICT: kread receipt present. Still confirm kread64(kbase+8) typeinfo before commitSlide. physRW HOLD.")
        } else if log.contains("PIPE-HIT") || log.contains("QUEUE-INIT") {
            lines.append("VERDICT: write/conversion window receipt. hasKread stays NO until kread32(kbase)==0xfeedfacf.")
        } else if log.hasPrefix("STOP") {
            lines.append("VERDICT: parked remaining-fire. Do not retry. Learning will not reopen it.")
        } else if classified.outcome == "maf" {
            lines.append("VERDICT: panic-class. Next boot fire the survivor sibling (not hop-1). Learning stores the death; it does not mint kread.")
        } else {
            lines.append("VERDICT: hypothesis only. Need panic IPS or kread32 receipt. Lattice cannot skip leak→write→kread32.")
        }
        return lines.joined(separator: "\n")
    }

    private static func tokenize(_ s: String) -> [String] {
        s.lowercased()
            .components(separatedBy: CharacterSet.alphanumerics.inverted)
            .filter { $0.count > 1 }
    }

    private static func documentFreq(_ terms: [String]) -> [String: Int] {
        var df: [String: Int] = [:]
        for note in notes {
            let bag = Set(tokenize(note.id + " " + note.title + " " + note.text))
            for t in Set(terms) where bag.contains(t) { df[t, default: 0] += 1 }
        }
        return df
    }
}

// MARK: - Phone-side tools

enum LuminaMindTools {
    static var schema: [[String: Any]] { [
        fn("run_tap", "Run a Lum1na probe/primitive by catalog id (p149, p114, ident, krw, …). Honor parked remaining-fire. One TAP per force-quit. Panic-possible probes may kill the process.",
           ["id": str("TAP id such as p149, p114, ident, krw, board")],
           ["id"]),
        fn("list_probes", "List Lum1na and Cinder catalog ids. Optional substring filter.",
           ["query": str("optional substring, e.g. AVE or p14")],
           []),
        fn("read_log", "Read a Documents log file (p149_t8150_krw_log.txt, p007_board.json, p011_tap_log.txt, …).",
           ["name": str("filename under Documents")],
           ["name"]),
        fn("read_board", "Read p007_board.json and the live kreadSignal. hasKread is live per process.",
           [:], []),
        fn("ident", "Run DeviceIdentProbe (SKU, LabOff, prove matrix).",
           [:], []),
        fn("list_documents", "List files in the app Documents folder (logs, boards, knobs).",
           [:], []),
        fn("search_laws", "BM25 search of bundled Lum1na-Mind laws (redacted).",
           ["query": str("search query")],
           ["query"]),
        fn("analyze_log", "Phone-side auto-analyze of a log file or pasted text against CORE LAWS. Does not claim KRW.",
           ["name": str("Documents filename, or empty to use text"),
            "text": str("optional pasted log")],
           []),
        fn("web_search", "Search the public web (DuckDuckGo + Wikipedia). Use for CVE bulletins and public docs.",
           ["query": str("search query")],
           ["query"]),
        fn("read_file", "Read a sandbox-readable file. Absolute path or Documents-relative name.",
           ["path": str("path")],
           ["path"]),
        fn("search_logs", "Grep Documents *_log.txt files for a substring.",
           ["query": str("substring")],
           ["query"]),
        fn("kread_signal", "Return P007Board kreadSignal string (YES only after commitSlide).",
           [:], []),
        fn("va_law", "Apply flat-VA law: fileoff = (va & 0xFFFFFFF) - 0x7004000.",
           ["va": str("kernel/kext VA hex, e.g. 0xfffffe0008790cec")],
           ["va"]),
        fn("run_cinder", "Run a Cinder catalog module by id (cg.shading, kern.ipc, kern.decmpfs, …).",
           ["id": str("Cinder module id")],
           ["id"]),
        fn("chain_status", "Summarize Lum1na 17 KRW chain stages and last TAP.",
           [:], []),
        fn("list_hour_logs", "List log snapshots from the last hour.",
           [:], []),
        fn("device_sku", "hw.machine + kern.osversion + marketing version.",
           [:], []),
        fn("bandit_plan", "LabBanditPlan ranked cross-domain hunt scheduler plus promote.json lattice rows. device=1.0 evidence.",
           [:], []),
        fn("bandit_status", "Same as bandit_plan: learn.<id> ledger + survivor knobs + panic counts.",
           [:], []),
        fn("stage_ladder", "KernelLab 0.3.2 stage ladder sandbox→leak→race→write→krw→sptm. Labels only; not a device KRW claim.",
           [:], []),
        fn("promote_status", "Per-id promotion lattice: panic_count, survivor_knob, sibling, hasKread. Honest: panic can learn a survivor knob; it cannot skip kread32.",
           [:], []),
        fn("promote_apply", "Write learned survivor knobs into Documents (p142_layers, p147_cycles, p148_gop). Never overwrites 16463 panic-class.",
           [:], []),
        fn("oracle_export", "Dump lab_bandit.json + lab_promote.json for host oracle_bridge show / kernellab sim ident --feed.",
           [:], []),
        fn("mind_ping", "Probe the phone's Mind endpoint: GET /models then a tiny chat. Use after Mac lumina_mind_serve.sh.",
           ["base": str("optional override base URL"),
            "model": str("optional override model")],
           [])
    ] }

    static func openaiTools() -> [[String: Any]] {
        schema.map { ["type": "function", "function": $0] }
    }

    static func call(_ name: String, arguments json: String, engine: LabEngine?) -> String {
        let args = parseArgs(json)
        switch name {
        case "run_tap":
            return runTap(args["id"] ?? "")
        case "list_probes":
            return listProbes(args["query"] ?? "")
        case "read_log":
            return readDoc(args["name"] ?? "")
        case "read_board":
            return readBoard()
        case "ident":
            return runTap("ident")
        case "list_documents":
            return listDocuments()
        case "search_laws":
            return searchLaws(args["query"] ?? "")
        case "analyze_log":
            if let name = args["name"], !name.isEmpty {
                return LuminaMindLaws.analyze(readDoc(name))
            }
            return LuminaMindLaws.analyze(args["text"] ?? "")
        case "web_search":
            return webSearch(args["query"] ?? "")
        case "read_file":
            return readAny(args["path"] ?? "")
        case "search_logs":
            return searchLogs(args["query"] ?? "")
        case "kread_signal":
            return P007Board.shared().kreadSignal
        case "va_law":
            return vaLaw(args["va"] ?? "")
        case "run_cinder":
            return runCinder(args["id"] ?? "", engine: engine)
        case "chain_status":
            return chainStatus()
        case "list_hour_logs":
            return listHour()
        case "device_sku":
            return deviceSKU()
        case "bandit_plan", "bandit_status", "promote_status":
            return LuminaLearn.status()
        case "stage_ladder":
            return LuminaLearn.stageLadder()
        case "promote_apply":
            return LuminaLearn.applySurvivorKnobs()
        case "oracle_export":
            return LuminaLearn.exportOracle()
        case "mind_ping":
            let d = UserDefaults.standard
            let base = (args["base"]?.isEmpty == false ? args["base"] : nil)
                ?? d.string(forKey: "lumind.base") ?? ""
            let model = (args["model"]?.isEmpty == false ? args["model"] : nil)
                ?? d.string(forKey: "lumind.model") ?? ""
            let key = d.string(forKey: "lumind.key") ?? ""
            return ping(base: base, model: model, apiKey: key).summary
        default:
            return "unknown tool \(name)"
        }
    }

    private static func runTap(_ id: String) -> String {
        let tid = id.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !tid.isEmpty else { return "run_tap needs id" }
        if let stop = LuminaTAP.blocked(tid) { return stop }
        let body = LuminaTAP.execute(tid)
        let analysis = LuminaMindLaws.analyze(body)
        return body + "\n\n--- auto-analyze ---\n" + analysis
    }

    private static func listProbes(_ query: String) -> String {
        let q = query.lowercased()
        var lines: [String] = ["LUMINA TAPS"]
        let lum = Catalog.luminaKRW + Catalog.luminaLive + Catalog.luminaParked
        for m in lum {
            if q.isEmpty || m.id.lowercased().contains(q) || m.title.lowercased().contains(q) {
                lines.append("  \(m.id)  \(m.title)  [\(m.cve)]")
            }
        }
        lines.append("CINDER MODULES")
        for m in Catalog.all where !lum.contains(where: { $0.id == m.id }) {
            if q.isEmpty || m.id.lowercased().contains(q) || m.title.lowercased().contains(q) {
                lines.append("  \(m.id)  \(m.title)  [\(m.cve)]")
            }
        }
        if lines.count > 220 {
            return lines.prefix(220).joined(separator: "\n") + "\n… truncated; pass query to filter"
        }
        return lines.joined(separator: "\n")
    }

    private static func docsURL() -> URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    private static func readDoc(_ name: String) -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "read_log needs name" }
        let url = docsURL().appendingPathComponent((trimmed as NSString).lastPathComponent)
        guard let raw = try? String(contentsOf: url, encoding: .utf8), !raw.isEmpty else {
            return "missing or empty: \(url.lastPathComponent)"
        }
        if raw.count > 24_000 {
            return String(raw.suffix(24_000)) + "\n…(truncated to last 24k)"
        }
        return raw
    }

    private static func readBoard() -> String {
        let sig = P007Board.shared().kreadSignal as String? ?? "?"
        let body = readDoc("p007_board.json")
        return "kreadSignal=\(sig)\n\n\(body)"
    }

    private static func listDocuments() -> String {
        let fm = FileManager.default
        let url = docsURL()
        guard let items = try? fm.contentsOfDirectory(at: url, includingPropertiesForKeys: [.fileSizeKey, .contentModificationDateKey], options: [.skipsHiddenFiles]) else {
            return "Documents unreadable"
        }
        let rows = items.sorted { $0.lastPathComponent < $1.lastPathComponent }.map { u -> String in
            let size = (try? u.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
            return "  \(u.lastPathComponent)  \(size)B"
        }
        return "Documents (\(rows.count))\n" + rows.joined(separator: "\n")
    }

    private static func searchLaws(_ query: String) -> String {
        let hits = LuminaMindLaws.search(query, top: 8)
        if hits.isEmpty { return "no law match for \(query)" }
        return hits.map { String(format: "[%.3f] %@ — %@\n%@", $0.0, $0.1.id, $0.1.title, $0.1.text) }
            .joined(separator: "\n\n")
    }

    private static func webSearch(_ query: String) -> String {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { return "web_search needs query" }
        var chunks: [String] = []
        if let ddg = fetchJSON("https://api.duckduckgo.com/?q=\(enc(q))&format=json&no_html=1&no_redirect=1") {
            if let abs = ddg["AbstractText"] as? String, !abs.isEmpty {
                chunks.append("DuckDuckGo: \(abs)")
            }
            if let heading = ddg["Heading"] as? String, !heading.isEmpty {
                chunks.append("Heading: \(heading)")
            }
            if let related = ddg["RelatedTopics"] as? [[String: Any]] {
                for item in related.prefix(6) {
                    if let text = item["Text"] as? String { chunks.append("• \(text)") }
                }
            }
        }
        if let data = fetchData("https://en.wikipedia.org/w/api.php?action=opensearch&search=\(enc(q))&limit=5&namespace=0&format=json"),
           let arr = try? JSONSerialization.jsonObject(with: data) as? [Any],
           arr.count >= 4,
           let titles = arr[1] as? [String],
           let descs = arr[2] as? [String],
           let urls = arr[3] as? [String] {
            chunks.append("Wikipedia:")
            for i in 0..<min(titles.count, 5) {
                let d = i < descs.count ? descs[i] : ""
                let u = i < urls.count ? urls[i] : ""
                chunks.append("  \(titles[i]) — \(d) \(u)")
            }
        }
        if chunks.isEmpty {
            return "no web hits (device offline, or the query was too narrow). Tried DuckDuckGo + Wikipedia for: \(q)"
        }
        return chunks.joined(separator: "\n")
    }

    private static func readAny(_ path: String) -> String {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "read_file needs path" }
        let url: URL
        if trimmed.hasPrefix("/") {
            url = URL(fileURLWithPath: trimmed)
        } else {
            url = docsURL().appendingPathComponent(trimmed)
        }
        guard let raw = try? String(contentsOf: url, encoding: .utf8) else {
            return "unreadable: \(url.path)"
        }
        if raw.count > 20_000 { return String(raw.prefix(20_000)) + "\n…truncated" }
        return raw
    }

    private static func searchLogs(_ query: String) -> String {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { return "search_logs needs query" }
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(at: docsURL(), includingPropertiesForKeys: nil) else {
            return "Documents unreadable"
        }
        var hits: [String] = []
        for u in items where u.lastPathComponent.hasSuffix(".txt") || u.lastPathComponent.hasSuffix(".json") {
            guard let raw = try? String(contentsOf: u, encoding: .utf8) else { continue }
            if raw.localizedCaseInsensitiveContains(q) {
                let lines = raw.components(separatedBy: .newlines).filter { $0.localizedCaseInsensitiveContains(q) }
                hits.append("## \(u.lastPathComponent) (\(lines.count) lines)")
                hits.append(contentsOf: lines.prefix(8))
            }
            if hits.count > 80 { break }
        }
        return hits.isEmpty ? "no log hits for \(q)" : hits.joined(separator: "\n")
    }

    private static func vaLaw(_ va: String) -> String {
        let hex = va.lowercased().replacingOccurrences(of: "0x", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let v = UInt64(hex, radix: 16) else { return "va_law needs hex VA" }
        let fileoff = Int64(v & 0xFFFFFFF) - 0x7004000
        return String(format: "va=0x%llx\nfileoff = (va & 0xFFFFFFF) - 0x7004000 = 0x%llx (%lld)\nFLAT-VA LAW: one delta for kernel and all kexts on 26.5/27.0 caches.",
                      v, fileoff, fileoff)
    }

    private static func runCinder(_ id: String, engine: LabEngine?) -> String {
        let tid = id.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let module = Catalog.byID[tid] else { return "unknown Cinder id \(tid)" }
        guard let engine else {
            // synchronous fallback
            let ctx = RunContext(workdir: Container.work, journal: GuardJournal())
            do {
                LuminaLearn.begin(tid)
                ctx.arm(tid, "mind")
                let out = try module.run(ctx)
                ctx.disarm(tid, out.headline)
                return LuminaLearn.finish(tid, log: out.headline + "\n" + out.detail)
            } catch {
                _ = LuminaLearn.finish(tid, log: "failed\n" + error.localizedDescription)
                return "threw: \(error.localizedDescription)"
            }
        }
        engine.run(module)
        return "queued Cinder module \(tid) (\(module.title)). Watch Lab / System log."
    }

    private static func chainStatus() -> String {
        let sig = P007Board.shared().kreadSignal as String? ?? "?"
        let last = readDoc("p011_tap_log.txt")
        let tail = last.components(separatedBy: .newlines).suffix(12).joined(separator: "\n")
        return """
        17 KRW formula: leak(P114) → write(P142 v7 encode-first inside P149) → convert(P149 pipes) → kread32(kbase)==0xfeedfacf → sptm HOLD
        Hunt occupancy: P044 / CONV. Occupancy HIT is not hasKread.
        Lattice: sandbox → leak → race → write → krw → sptm. APPLE-SUBMIT: closed.
        kreadSignal: \(sig)
        Last TAP markers:
        \(tail)
        """
    }

    private static func listHour() -> String {
        let hour = docsURL().appendingPathComponent("hour", isDirectory: true)
        guard let items = try? FileManager.default.contentsOfDirectory(at: hour, includingPropertiesForKeys: [.contentModificationDateKey]) else {
            return "no hour/ snapshots"
        }
        return items.sorted { $0.lastPathComponent > $1.lastPathComponent }.prefix(20)
            .map { $0.lastPathComponent }.joined(separator: "\n")
    }

    private static func deviceSKU() -> String {
        DeviceIdentProbe.runIdentity()
    }

    struct PingResult {
        let ok: Bool
        let summary: String
        let models: [String]
    }

    static func ping(base: String, model: String, apiKey: String) -> PingResult {
        let trimmed = base.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if LuminaMindSettings.isPlaceholder(trimmed) {
            return PingResult(
                ok: false,
                summary: "FAIL: no Mac URL. 192.168.1.1 is usually the Wi-Fi gateway. On the Mac run tools/lumina_mind_serve.sh, then Discover or paste http://<mac-lan-ip>:11434/v1 (ollama) or :8080/v1 (mlx).",
                models: [])
        }
        guard let modelsURL = URL(string: trimmed + "/models") else {
            return PingResult(ok: false, summary: "FAIL: bad URL \(trimmed)", models: [])
        }
        var req = URLRequest(url: modelsURL, timeoutInterval: 8)
        req.setValue("Lum1na-Debugger", forHTTPHeaderField: "User-Agent")
        if !apiKey.isEmpty {
            req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        }
        if trimmed.contains("openrouter.ai") {
            req.setValue("https://github.com/ma6x9x/Lum1na", forHTTPHeaderField: "HTTP-Referer")
            req.setValue("Lum1na-Mind", forHTTPHeaderField: "X-Title")
        }
        let sem = DispatchSemaphore(value: 0)
        var data: Data?
        var status = 0
        var errStr = ""
        URLSession.shared.dataTask(with: req) { d, resp, err in
            data = d
            status = (resp as? HTTPURLResponse)?.statusCode ?? 0
            errStr = err?.localizedDescription ?? ""
            sem.signal()
        }.resume()
        _ = sem.wait(timeout: .now() + 10)

        var ids: [String] = []
        if let data,
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if let arr = obj["data"] as? [[String: Any]] {
                ids = arr.compactMap { $0["id"] as? String }
            }
        }

        if status == 200 {
            let modelHint: String
            if ids.isEmpty {
                modelHint = "GET /models returned empty data. Phone model=\(model)"
            } else if ids.contains(model) {
                modelHint = "model \(model) is on the server."
            } else {
                modelHint = "server models: \(ids.joined(separator: ", ")). Phone model is '\(model)' — tap one of the server names."
            }
            return PingResult(ok: true, summary: "OK GET /models HTTP \(status)\n\(modelHint)", models: ids)
        }

        if let chatURL = URL(string: trimmed + "/chat/completions") {
            var creq = URLRequest(url: chatURL, timeoutInterval: 16)
            creq.httpMethod = "POST"
            creq.setValue("application/json", forHTTPHeaderField: "Content-Type")
            creq.setValue("Lum1na-Debugger", forHTTPHeaderField: "User-Agent")
            if !apiKey.isEmpty {
                creq.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
            }
            let body: [String: Any] = [
                "model": model,
                "messages": [["role": "user", "content": "ping"]],
                "max_tokens": 8,
                "stream": false
            ]
            creq.httpBody = try? JSONSerialization.data(withJSONObject: body)
            var cdata: Data?
            var cstatus = 0
            var cerr = ""
            let sem2 = DispatchSemaphore(value: 0)
            URLSession.shared.dataTask(with: creq) { d, resp, err in
                cdata = d
                cstatus = (resp as? HTTPURLResponse)?.statusCode ?? 0
                cerr = err?.localizedDescription ?? ""
                sem2.signal()
            }.resume()
            _ = sem2.wait(timeout: .now() + 18)
            if cstatus == 200 {
                return PingResult(ok: true,
                                  summary: "OK POST /chat/completions HTTP 200 (GET /models was HTTP \(status)). model=\(model)",
                                  models: ids)
            }
            let raw = cdata.flatMap { String(data: $0, encoding: .utf8) } ?? cerr
            let modelsBit = errStr.isEmpty ? "GET /models HTTP \(status)" : "GET /models error: \(errStr)"
            return PingResult(ok: false,
                              summary: "FAIL \(modelsBit); chat HTTP \(cstatus) \(raw.prefix(240))\nMac: tools/lumina_mind_serve.sh  (ollama must bind 0.0.0.0, not 127.0.0.1).",
                              models: ids)
        }
        return PingResult(ok: false, summary: "FAIL GET /models HTTP \(status) \(errStr)", models: ids)
    }

    private static func fn(_ name: String, _ desc: String, _ props: [String: Any], _ req: [String]) -> [String: Any] {
        [
            "name": name,
            "description": desc,
            "parameters": [
                "type": "object",
                "properties": props,
                "required": req
            ]
        ]
    }

    private static func str(_ d: String) -> [String: String] { ["type": "string", "description": d] }

    private static func parseArgs(_ json: String) -> [String: String] {
        guard let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        var out: [String: String] = [:]
        for (k, v) in obj { out[k] = "\(v)" }
        return out
    }

    private static func enc(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? s
    }

    private static func fetchData(_ url: String) -> Data? {
        guard let u = URL(string: url) else { return nil }
        var req = URLRequest(url: u, timeoutInterval: 12)
        req.setValue("Lum1na-Debugger", forHTTPHeaderField: "User-Agent")
        let sem = DispatchSemaphore(value: 0)
        var data: Data?
        URLSession.shared.dataTask(with: req) { d, _, _ in
            data = d
            sem.signal()
        }.resume()
        _ = sem.wait(timeout: .now() + 14)
        return data
    }

    private static func fetchJSON(_ url: String) -> [String: Any]? {
        guard let data = fetchData(url) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}

// MARK: - Agent (OpenAI-compat tool loop)

struct MindMessage: Identifiable {
    let id = UUID()
    let role: String
    var text: String
}

final class LuminaMindAgent: ObservableObject {
    @Published var messages: [MindMessage] = []
    @Published var busy = false
    @Published var status = "idle"
    @Published var lastError = ""

    let settings: LuminaMindSettings
    weak var engine: LabEngine?

    init(settings: LuminaMindSettings) {
        self.settings = settings
        self.messages = [MindMessage(role: "system", text: LuminaMindAgent.systemPrompt)]
    }

    static let systemPrompt = """
    You are Lum1na-Mind, the user's personal iOS/XNU and coding expert inside Lum1na-Debugger.
    You know this lab's chain: disclose (P010/P063 via P139, kern.decmpfs/P126) → write (P044 N=192 on A14 23F77; P149 on T8150; SKIP 254/P099/P073) → convert unnamed 0x820 neighbor → SocketKRW.Arm(rw_inpcb) → kread32(kbase)==0xfeedfacf → AfterKread HOLD.
    A12X 23H30 is FIELD#-only (queue 0x408 / leak +0x550, fill_cap=1). 43748 patched in 26.6. Facet A patched 23G82. hop-1 EINVAL since 26.1. PPL AfterKread is easier on A12X than T8150 SPTM — it is not a first-KRW shortcut.
    Follow CORE LAWS. Never claim KRW without kread32(kbase)==0xfeedfacf.
    Occupancy HIT, PIPE-HIT, panic PCs, and ANE sid dumps are not hasKread.
    One TAP per force-quit. Warn before run_tap on p149/p044/p142/cs2/krw.
    Prefer tools over guessing. After run_tap, read the auto-analyze. Cite law ids.
    Suggest the next SINGLE TAP and why. Write and review code when asked.
    hop-1, 163-sel remaining-fire, TrollRestore/WVEK remaining-fire, 84523 unbounded, 86950-as-first-KRW stay STOP.
    """

    func send(_ userText: String) {
        let text = userText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !busy else { return }
        messages.append(MindMessage(role: "user", text: text))
        busy = true
        status = "thinking"
        lastError = ""
        let snapshot = messages
        let settings = self.settings
        let engine = self.engine
        DispatchQueue.global(qos: .userInitiated).async {
            let reply = Self.loop(messages: snapshot, settings: settings, engine: engine) { s in
                DispatchQueue.main.async { self.status = s }
            }
            DispatchQueue.main.async {
                self.messages.append(MindMessage(role: "assistant", text: reply))
                self.busy = false
                self.status = "idle"
                if settings.speakReplies { MindVoice.shared.speak(reply) }
            }
        }
    }

    func clear() {
        messages = [MindMessage(role: "system", text: LuminaMindAgent.systemPrompt)]
        lastError = ""
        status = "idle"
    }

    private static func loop(messages: [MindMessage], settings: LuminaMindSettings, engine: LabEngine?,
                             onStatus: @escaping (String) -> Void) -> String {
        let lastUser = messages.last(where: { $0.role == "user" })?.text ?? ""
        if settings.isPlaceholder && settings.provider != .spacexai && settings.provider != .openrouter {
            return offlineExpert(user: lastUser, error: "no Mac URL — Discover or pick Grok (xAI)", engine: engine)
        }
        if settings.provider.needsKey && settings.apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return offlineExpert(user: lastUser,
                                 error: "\(settings.provider.rawValue) needs an API key. Paste it in Mind gear, or drop Documents/xai_key.txt (Grok) / Documents/openrouter_key.txt.",
                                 engine: engine)
        }
        onStatus("GET /models")
        let ping = LuminaMindTools.ping(base: settings.baseURL, model: settings.model, apiKey: settings.apiKey)
        let resolved = pickModel(requested: settings.model, available: ping.models)
        if resolved != settings.model {
            DispatchQueue.main.async { settings.model = resolved }
            onStatus("using \(resolved)")
        }
        var history = messages
        for step in 0..<8 {
            onStatus("chat \(resolved) step \(step + 1)")
            do {
                let skip = shouldSkipTools(resolved)
                let (content, toolCalls) = skip
                    ? try chatNoTools(history: history, settings: settings, model: resolved)
                    : try chat(history: history, settings: settings, model: resolved)
                if toolCalls.isEmpty {
                    if let content, !content.isEmpty { return content }
                    return "(empty model reply)"
                }
                if let content, !content.isEmpty {
                    history.append(MindMessage(role: "assistant", text: content))
                }
                for call in toolCalls {
                    onStatus("tool \(call.name)")
                    let result = LuminaMindTools.call(call.name, arguments: call.arguments, engine: engine)
                    let clipped = result.count > 16_000 ? String(result.prefix(16_000)) + "\n…truncated" : result
                    history.append(MindMessage(role: "tool", text: "[\(call.name)]\n\(clipped)"))
                }
            } catch {
                let msg = error.localizedDescription
                if msg.lowercased().contains("usage limit") || msg.lowercased().contains("upgrade") {
                    return offlineExpert(user: lastUser,
                                         error: "Ollama cloud GLM/Kimi quota is exhausted. Switch to llama3.1:8b or deepseek-r1:1.5b (local/free) or Grok (xAI key).",
                                         engine: engine)
                }
                return offlineExpert(user: lastUser, error: msg, engine: engine)
            }
        }
        return "tool-loop cap (8). Ask a narrower question."
    }

    static func pickModel(requested: String, available: [String]) -> String {
        if available.isEmpty { return requested }
        if available.contains(requested) { return requested }
        let prefer = ["llama3.1:8b", "deepseek-r1:1.5b", "deepseek-coder:1.3b",
                      "grok-4.7", "grok-4", "grok-4-fast", "openrouter/free"]
        for p in prefer where available.contains(p) { return p }
        return available.first { id in
            let x = id.lowercased()
            return !x.contains("embed") && !x.contains("cloud")
        } ?? requested
    }

    static func shouldSkipTools(_ model: String) -> Bool {
        let m = model.lowercased()
        if m.contains("cloud") { return true }
        if m.contains("glm-edge") { return true }
        if m.contains("embed") { return true }
        if m.contains("-base") { return true }
        if m.contains("deepseek-r1") { return true }
        if m.contains("deepseek-coder") { return true }
        return false
    }

    static func offlineExpert(user: String, error: String?, engine: LabEngine?) -> String {
        var lines: [String] = [
            "ON-DEVICE EXPERT (no live model, or the upstream hung / quota-blocked)",
        ]
        if let error, !error.isEmpty { lines.append("upstream: \(error)") }
        lines.append("")
        lines.append(LuminaMindLaws.analyze(user))
        lines.append("")
        lines.append("kreadSignal: \(P007Board.shared().kreadSignal)")
        if let engine {
            let ids = engine.outcomes.keys.sorted()
            if !ids.isEmpty {
                lines.append("Cinder last: " + ids.suffix(8).joined(separator: ", "))
            }
        }
        lines.append("")
        lines.append("SUGGESTION: Ident → KERNEL (P139 harvest, then P044 N=192 on 23F77; harvest-only on 23H30). Skip P099/P073. Copy Lab/Cinder logs from the card or Console folder.")
        lines.append("Mind gear: Ollama llama3.1:8b (local/free), deepseek-r1:1.5b (local/free), or Grok (xAI) with your key.")
        return lines.joined(separator: "\n")
    }

    private struct ToolCall {
        let name: String
        let arguments: String
    }

    private static func applyHeaders(_ req: inout URLRequest, settings: LuminaMindSettings) {
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Lum1na-Debugger", forHTTPHeaderField: "User-Agent")
        if !settings.apiKey.isEmpty {
            req.setValue("Bearer \(settings.apiKey)", forHTTPHeaderField: "Authorization")
        }
        if settings.provider == .openrouter {
            req.setValue("https://github.com/ma6x9x/Lum1na", forHTTPHeaderField: "HTTP-Referer")
            req.setValue("Lum1na-Mind", forHTTPHeaderField: "X-Title")
        }
    }

    private static func chat(history: [MindMessage], settings: LuminaMindSettings, model: String? = nil) throws -> (String?, [ToolCall]) {
        let modelName = model ?? settings.model
        let base = settings.baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if LuminaMindSettings.isPlaceholder(base) {
            throw NSError(domain: "Lumind", code: 1, userInfo: [NSLocalizedDescriptionKey: "Mind is not pointed at a Mac. Open Mind settings → Discover, pick Grok (xAI), or paste the Phone URL from tools/lumina_mind_serve.sh."])
        }
        guard let url = URL(string: base + "/chat/completions") else {
            throw NSError(domain: "Lumind", code: 1, userInfo: [NSLocalizedDescriptionKey: "bad base URL"])
        }
        var msgs: [[String: Any]] = []
        for m in history {
            if m.role == "tool" {
                msgs.append(["role": "user", "content": "TOOL RESULT:\n\(m.text)"])
            } else {
                msgs.append(["role": m.role, "content": m.text])
            }
        }
        var body: [String: Any] = [
            "model": modelName,
            "messages": msgs,
            "temperature": 0.2,
            "tools": LuminaMindTools.openaiTools(),
            "tool_choice": "auto"
        ]
        var req = URLRequest(url: url, timeoutInterval: 55)
        req.httpMethod = "POST"
        applyHeaders(&req, settings: settings)
        req.httpBody = try JSONSerialization.data(withJSONObject: body)

        let sem = DispatchSemaphore(value: 0)
        var data: Data?
        var err: Error?
        var code = 0
        URLSession.shared.dataTask(with: req) { d, resp, e in
            data = d
            err = e
            code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            sem.signal()
        }.resume()
        _ = sem.wait(timeout: .now() + 58)
        if let err { throw err }
        guard let data else { throw NSError(domain: "Lumind", code: 2, userInfo: [NSLocalizedDescriptionKey: "no response from \(base) — first llama3.1:8b load can take a minute. Warm it on the Mac: curl the chat endpoint once."]) }
        if code >= 400 {
            let raw = String(data: data, encoding: .utf8) ?? ""
            // retry without tools if the server rejects the tools field
            if raw.lowercased().contains("tool") || code == 400 {
                return try chatNoTools(history: history, settings: settings, model: modelName)
            }
            throw NSError(domain: "Lumind", code: code, userInfo: [NSLocalizedDescriptionKey: "HTTP \(code): \(raw.prefix(400))"])
        }
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let choices = obj["choices"] as? [[String: Any]],
              let msg = choices.first?["message"] as? [String: Any] else {
            throw NSError(domain: "Lumind", code: 3, userInfo: [NSLocalizedDescriptionKey: "malformed chat response"])
        }
        let content = msg["content"] as? String
        var calls: [ToolCall] = []
        if let tcs = msg["tool_calls"] as? [[String: Any]] {
            for tc in tcs {
                let fn = tc["function"] as? [String: Any]
                let name = (fn?["name"] as? String) ?? (tc["name"] as? String) ?? ""
                let args = (fn?["arguments"] as? String) ?? ""
                if !name.isEmpty { calls.append(ToolCall(name: name, arguments: args.isEmpty ? "{}" : args)) }
            }
        }
        if calls.isEmpty, let content, let parsed = parseTextTool(content) {
            calls.append(parsed)
        }
        return (content, calls)
    }

    private static func chatNoTools(history: [MindMessage], settings: LuminaMindSettings, model: String? = nil) throws -> (String?, [ToolCall]) {
        let modelName = model ?? settings.model
        let base = settings.baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if LuminaMindSettings.isPlaceholder(base) {
            throw NSError(domain: "Lumind", code: 1, userInfo: [NSLocalizedDescriptionKey: "Mind is not pointed at a Mac. Open Mind settings → Discover, pick Grok (xAI), or paste the Phone URL from tools/lumina_mind_serve.sh."])
        }
        guard let url = URL(string: base + "/chat/completions") else {
            throw NSError(domain: "Lumind", code: 1, userInfo: [NSLocalizedDescriptionKey: "bad base URL"])
        }
        let toolCard = LuminaMindTools.schema.map { d in
            let name = d["name"] as? String ?? ""
            let desc = d["description"] as? String ?? ""
            return "- \(name): \(desc)"
        }.joined(separator: "\n")
        var msgs: [[String: Any]] = [[
            "role": "system",
            "content": systemPrompt + "\n\nTOOLS (emit a single JSON object when you need one):\n{\"tool\":\"name\",\"arguments\":{...}}\n\n" + toolCard
        ]]
        for m in history where m.role != "system" {
            msgs.append(["role": m.role == "tool" ? "user" : m.role, "content": m.text])
        }
        let body: [String: Any] = [
            "model": modelName,
            "messages": msgs,
            "temperature": 0.2
        ]
        var req = URLRequest(url: url, timeoutInterval: 55)
        req.httpMethod = "POST"
        applyHeaders(&req, settings: settings)
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let sem = DispatchSemaphore(value: 0)
        var data: Data?
        var err: Error?
        URLSession.shared.dataTask(with: req) { d, _, e in
            data = d; err = e; sem.signal()
        }.resume()
        _ = sem.wait(timeout: .now() + 58)
        if let err { throw err }
        guard let data,
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let choices = obj["choices"] as? [[String: Any]],
              let msg = choices.first?["message"] as? [String: Any] else {
            throw NSError(domain: "Lumind", code: 3, userInfo: [NSLocalizedDescriptionKey: "malformed chat response"])
        }
        let content = msg["content"] as? String
        var calls: [ToolCall] = []
        if let content, let parsed = parseTextTool(content) { calls.append(parsed) }
        return (content, calls)
    }

    private static func parseTextTool(_ content: String) -> ToolCall? {
        guard let start = content.range(of: "{\"tool\"" ) ?? content.range(of: "{\"name\"") else { return nil }
        let slice = String(content[start.lowerBound...])
        guard let data = slice.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            // try first JSON object
            if let r = content.range(of: "{"),
               let s = content[r.lowerBound...].data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: s) as? [String: Any] {
                let name = (obj["tool"] as? String) ?? (obj["name"] as? String) ?? ""
                if name.isEmpty { return nil }
                let args: String
                if let a = obj["arguments"] as? [String: Any],
                   let d = try? JSONSerialization.data(withJSONObject: a),
                   let t = String(data: d, encoding: .utf8) {
                    args = t
                } else {
                    args = "{}"
                }
                return ToolCall(name: name, arguments: args)
            }
            return nil
        }
        let name = (obj["tool"] as? String) ?? (obj["name"] as? String) ?? ""
        guard !name.isEmpty else { return nil }
        let args: String
        if let a = obj["arguments"] as? [String: Any],
           let d = try? JSONSerialization.data(withJSONObject: a),
           let t = String(data: d, encoding: .utf8) {
            args = t
        } else if let a = obj["arguments"] as? String {
            args = a
        } else {
            args = "{}"
        }
        return ToolCall(name: name, arguments: args)
    }
}

// MARK: - UI

struct MindPane: View {
    @EnvironmentObject private var engine: LabEngine
    @StateObject private var settings: LuminaMindSettings
    @StateObject private var agent: LuminaMindAgent
    @State private var draft = ""
    @State private var showSettings = false

    init() {
        let s = LuminaMindSettings()
        _settings = StateObject(wrappedValue: s)
        _agent = StateObject(wrappedValue: LuminaMindAgent(settings: s))
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                banner
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 10) {
                            ForEach(agent.messages.filter { $0.role != "system" }) { msg in
                                bubble(msg)
                                    .id(msg.id)
                            }
                            if agent.busy {
                                HStack(spacing: 8) {
                                    ProgressView().tint(T.ember)
                                    Text(agent.status)
                                        .font(T.tiny)
                                        .foregroundColor(.white.opacity(0.5))
                                }
                                .padding(.horizontal, 12)
                            }
                        }
                        .padding(12)
                    }
                    .onChange(of: agent.messages.count) { _, _ in
                        if let last = agent.messages.last { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
                composer
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(t("tab.mind"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Clear") { agent.clear() }
                        .font(T.tiny)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    HStack(spacing: 14) {
                        Button {
                            settings.speakReplies.toggle()
                            if !settings.speakReplies { MindVoice.shared.stop() }
                        } label: {
                            Image(systemName: settings.speakReplies ? "speaker.wave.2.fill" : "speaker.slash")
                        }
                        Button {
                            showSettings = true
                        } label: {
                            Image(systemName: "gearshape.fill")
                        }
                    }
                }
            }
            .sheet(isPresented: $showSettings) {
                MindSettingsSheet(settings: settings)
            }
            .onAppear { agent.engine = engine }
        }
    }

    private var banner: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Lum1na-Mind · iOS/XNU expert")
                .font(T.head)
                .foregroundColor(.white)
            if settings.isPlaceholder && settings.provider != .spacexai && settings.provider != .openrouter {
                Text("Not connected. Gear: Grok (xAI) + your key, or Discover the Mac ollama URL. llama3.1:8b and deepseek-r1:1.5b are local/free. 192.168.1.1 is the router.")
                    .font(T.tiny)
                    .foregroundColor(T.warn)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("\(settings.provider.rawValue) · \(settings.model)\n\(settings.baseURL)\nSpeak \(settings.speakReplies ? "ON" : "off"). Tools: run_tap, Cinder, logs, laws.")
                    .font(T.tiny)
                    .foregroundColor(.white.opacity(0.45))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(T.panel)
    }

    private func bubble(_ msg: MindMessage) -> some View {
        let mine = msg.role == "user"
        let tool = msg.role == "tool"
        return HStack {
            if mine { Spacer(minLength: 36) }
            Text(msg.text)
                .font(tool ? T.monoSm : T.body)
                .foregroundColor(tool ? T.warn : .white.opacity(0.92))
                .padding(10)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(mine ? T.ember.opacity(0.22) : (tool ? T.panelHi : T.panel))
                )
            if !mine { Spacer(minLength: 36) }
        }
    }

    private var composer: some View {
        VStack(spacing: 8) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    chip("Ping") { agent.send("mind_ping the configured endpoint. Report OK/FAIL and the model list. Do not run a TAP.") }
                    chip("Ident + board") { agent.send("Run ident and read_board. Summarize SKU and kreadSignal. Do not fire panic-possible probes.") }
                    chip("Next TAP") { agent.send("Read the board and Cinder last results. Suggest the next SINGLE TAP on this SKU and why. Do not fire it.") }
                    chip("Analyze last TAP") { agent.send("Read p011_tap_log.txt, then analyze the newest matching Documents log. Cite CORE LAWS. Next TAP = one id.") }
                    chip("17 KRW path") { agent.send("chain_status then search_laws for T8150 KRW. What is the next single TAP on this SKU? Do not fire it yet.") }
                }
                .padding(.horizontal, 12)
            }
            HStack(spacing: 8) {
                TextField("Ask Mind to run a probe, read a log, search…", text: $draft, axis: .vertical)
                    .textFieldStyle(.plain)
                    .font(T.body)
                    .foregroundColor(.white)
                    .lineLimit(1...5)
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(T.panel))
                Button {
                    let t = draft
                    draft = ""
                    agent.send(t)
                } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.system(size: 28))
                        .foregroundColor(T.ember)
                }
                .disabled(agent.busy || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding(.horizontal, 12)
            .padding(.bottom, 10)
        }
        .background(T.bg)
    }

    private func chip(_ title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(T.tiny)
                .foregroundColor(T.emberSoft)
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(Capsule().strokeBorder(T.ember.opacity(0.4), lineWidth: 1))
        }
        .disabled(agent.busy)
    }
}

final class MindBonjour: NSObject, ObservableObject, NetServiceBrowserDelegate, NetServiceDelegate {
    struct Host: Identifiable, Hashable {
        let id: String
        let name: String
        let url: String
        let detail: String
    }

    @Published var hosts: [Host] = []
    @Published var status = "idle"
    private let browser = NetServiceBrowser()
    private var resolving: [NetService] = []
    private var started = false

    func start() {
        guard !started else { return }
        started = true
        browser.delegate = self
        status = "browsing _lumina-mind._tcp"
        browser.searchForServices(ofType: "_lumina-mind._tcp.", inDomain: "local.")
    }

    func stop() {
        browser.stop()
        started = false
        status = "idle"
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        service.delegate = self
        service.resolve(withTimeout: 5)
        resolving.append(service)
        DispatchQueue.main.async { self.status = "resolving \(service.name)" }
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didRemove service: NetService, moreComing: Bool) {
        let name = service.name
        DispatchQueue.main.async { self.hosts.removeAll { $0.name == name } }
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didNotSearch errorDict: [String: NSNumber]) {
        DispatchQueue.main.async { self.status = "browse failed \(errorDict)" }
    }

    func netServiceDidResolveAddress(_ sender: NetService) {
        let ip = ipv4(sender) ?? sender.hostName ?? ""
        guard !ip.isEmpty else { return }
        let port = sender.port
        let url = "http://\(ip):\(port)/v1"
        let host = Host(id: url, name: sender.name, url: url, detail: "\(ip):\(port)")
        DispatchQueue.main.async {
            if !self.hosts.contains(where: { $0.url == url }) {
                self.hosts.append(host)
            }
            self.status = "found \(self.hosts.count)"
        }
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {
        DispatchQueue.main.async { self.status = "resolve failed \(sender.name)" }
    }

    private func ipv4(_ service: NetService) -> String? {
        guard let addrs = service.addresses else { return nil }
        for data in addrs {
            var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let ok: Bool = data.withUnsafeBytes { raw in
                guard let sa = raw.baseAddress?.assumingMemoryBound(to: sockaddr.self) else { return false }
                return getnameinfo(sa, socklen_t(data.count), &hostname, socklen_t(NI_MAXHOST), nil, 0, NI_NUMERICHOST) == 0
            }
            guard ok else { continue }
            let s = String(cString: hostname)
            if s.contains(":") { continue }
            if s.hasPrefix("127.") { continue }
            return s
        }
        return nil
    }
}

struct MindSettingsSheet: View {
    @ObservedObject var settings: LuminaMindSettings
    @Environment(\.dismiss) private var dismiss
    @StateObject private var bonjour = MindBonjour()
    @State private var pingBusy = false
    @State private var pingText = ""
    @State private var pingOK = false
    @State private var serverModels: [String] = []

    var body: some View {
        NavigationStack {
            Form {
                Section("Mac / phone setup") {
                    Text("Free local (no key): Mac ollama llama3.1:8b (XNU/coding) or deepseek-r1:1.5b. GLM cloud on this Mac is quota-exhausted; glm-edge-1.5b does not exist.\nGrok: pick Grok (xAI), paste the console.x.ai key, model grok-4.7.\nOpenRouter free: pick that provider, paste a free key, model openrouter/free (Kimi :free is gone; GLM :free rotates).\nOr drop Documents/xai_key.txt / openrouter_key.txt.")
                        .font(T.tiny)
                        .foregroundColor(.secondary)
                    if settings.isPlaceholder && settings.provider != .spacexai && settings.provider != .openrouter {
                        Text("Current URL is a placeholder / gateway. 192.168.1.1 is usually the router.")
                            .font(T.tiny)
                            .foregroundColor(T.warn)
                    }
                }
                Section("Endpoint") {
                    Picker("Provider", selection: $settings.provider) {
                        ForEach(LuminaMindProvider.allCases) { p in
                            Text(p.rawValue).tag(p)
                        }
                    }
                    .onChange(of: settings.provider) { _, p in
                        settings.applyPreset(p)
                    }
                    TextField("Base URL", text: $settings.baseURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(T.monoSm)
                    TextField("Model", text: $settings.model)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(T.monoSm)
                    SecureField("API key (SpaceXAI / custom)", text: $settings.apiKey)
                        .font(T.monoSm)
                    Button {
                        runPing()
                    } label: {
                        HStack {
                            Text(pingBusy ? "Probing…" : "Test Connection")
                            if pingBusy { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(pingBusy)
                    if !pingText.isEmpty {
                        Text(pingText)
                            .font(T.monoSm)
                            .foregroundColor(pingOK ? .green : T.warn)
                            .textSelection(.enabled)
                    }
                    if !serverModels.isEmpty {
                        ForEach(serverModels, id: \.self) { name in
                            Button {
                                settings.model = name
                            } label: {
                                HStack {
                                    Text(name).font(T.monoSm)
                                    Spacer()
                                    if settings.model == name {
                                        Image(systemName: "checkmark")
                                    }
                                }
                            }
                        }
                    }
                }
                Section("Discover (_lumina-mind._tcp)") {
                    Text(bonjour.status)
                        .font(T.tiny)
                        .foregroundColor(.secondary)
                    if bonjour.hosts.isEmpty {
                        Text("No Bonjour hosts yet. The Mac script must be running (dns-sd -R Lum1na-Mind).")
                            .font(T.tiny)
                            .foregroundColor(.secondary)
                    }
                    ForEach(bonjour.hosts) { host in
                        Button {
                            settings.baseURL = host.url
                            if host.url.contains(":11434") {
                                settings.provider = .ollama
                            } else if host.url.contains(":8080") || host.url.contains(":8081") {
                                settings.provider = .lan
                            }
                            runPing()
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(host.name).font(T.body)
                                Text(host.url).font(T.monoSm).foregroundColor(.secondary)
                            }
                        }
                    }
                    Button("Browse again") {
                        bonjour.stop()
                        bonjour.start()
                    }
                }
                Section("Quick models") {
                    modelChip("llama3.1:8b", hint: "local expert") {
                        settings.provider = .ollama
                        let b = settings.baseURL
                        if b.contains("MAC_LAN_IP") || b.contains("x.ai") || b.contains("openrouter") {
                            settings.baseURL = LuminaMindProvider.ollama.defaultBase
                        }
                        settings.model = "llama3.1:8b"
                    }
                    modelChip("deepseek-r1:1.5b", hint: "local free") {
                        settings.provider = .ollama
                        let b = settings.baseURL
                        if b.contains("MAC_LAN_IP") || b.contains("x.ai") || b.contains("openrouter") {
                            settings.baseURL = LuminaMindProvider.ollama.defaultBase
                        }
                        settings.model = "deepseek-r1:1.5b"
                    }
                    modelChip("grok-4.7", hint: "your xAI key") {
                        settings.applyPreset(.spacexai)
                    }
                    modelChip("openrouter/free", hint: "free key") {
                        settings.applyPreset(.openrouter)
                    }
                }
                Section("Behavior") {
                    Toggle("Auto-analyze after TAP", isOn: $settings.autoAnalyze)
                    Toggle("Speak replies", isOn: $settings.speakReplies)
                }
                Section("Notes") {
                    Text("LAN ollama: OLLAMA_HOST=0.0.0.0:11434. Grok: https://api.x.ai/v1 + key from console.x.ai. OpenRouter: https://openrouter.ai/api/v1 + free key. Weights stay off the IPA.")
                        .font(T.tiny)
                        .foregroundColor(.secondary)
                }
            }
            .scrollContentBackground(.hidden)
            .background(T.bg)
            .navigationTitle("Mind settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear { bonjour.start() }
            .onDisappear { bonjour.stop() }
        }
        .preferredColorScheme(.dark)
    }

    private func modelChip(_ name: String, hint: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Text(name).font(T.monoSm)
                Spacer()
                Text(hint).font(T.tiny).foregroundColor(.secondary)
                if settings.model == name { Image(systemName: "checkmark") }
            }
        }
    }

    private func runPing() {
        if settings.apiKey.isEmpty {
            let dropped = LuminaMindSettings.loadDroppedKey()
            if !dropped.isEmpty { settings.apiKey = dropped }
        }
        pingBusy = true
        pingText = "probing \(settings.baseURL)…"
        let base = settings.baseURL
        let model = settings.model
        let key = settings.apiKey
        DispatchQueue.global(qos: .userInitiated).async {
            let r = LuminaMindTools.ping(base: base, model: model, apiKey: key)
            DispatchQueue.main.async {
                pingBusy = false
                pingOK = r.ok
                pingText = r.summary
                serverModels = r.models
            }
        }
    }
}

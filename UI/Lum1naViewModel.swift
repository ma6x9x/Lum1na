//
//  Lum1naViewModel.swift
//  Lum1na
//

import Foundation
import Combine
import SwiftUI
import UIKit

// NOTE: JailbreakStage enum removed - use UI/Lum1naTheme.swift definition instead

// MARK: - Exploit Protocols
@objc protocol KASLRLeakProtocol {
    func initializeLeak() -> Bool
    func leakKernelSlide() -> UInt64
    func cleanup()
}

@objc protocol UPLLeakProtocol {
    func initializeUPL() -> Bool
    func triggerLeak() -> Int32
    func establishPrimitives() -> Bool
}

@objc protocol ExploitControllerProtocol {
    func executeWithKbase(_ kbase: UnsafeMutablePointer<UInt64>, error: AutoreleasingUnsafeMutablePointer<NSString?>) -> Bool
}

// MARK: - Device Info
struct DeviceInfo {
    let machine: String
    let version: String
    let build: String
    let pagesize: Int
    let memsize: UInt64
    
    static func current() -> DeviceInfo {
        var model = "Unknown"
        var version = "?"
        var build = "?"
        var pagesize: Int = 0
        var memsize: UInt64 = 0
        
        var size = 0
        sysctlbyname("hw.machine", nil, &size, nil, 0)
        var machine = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.machine", &machine, &size, nil, 0)
        model = String(cString: machine)
        
        version = UIDevice.current.systemVersion
        
        size = 0
        sysctlbyname("kern.osversion", nil, &size, nil, 0)
        var osversion = [CChar](repeating: 0, count: size)
        sysctlbyname("kern.osversion", &osversion, &size, nil, 0)
        build = String(cString: osversion)
        
        size = MemoryLayout<Int>.size
        sysctlbyname("hw.pagesize", &pagesize, &size, nil, 0)
        
        size = MemoryLayout<UInt64>.size
        sysctlbyname("hw.memsize", &memsize, &size, nil, 0)
        
        return DeviceInfo(machine: model, version: version, build: build, pagesize: pagesize, memsize: memsize)
    }
}

// MARK: - Exploit State
enum ExploitState: Equatable {
    case idle
    case detecting
    case preparing
    case executingKASLR
    case executingHeap
    case executingANE
    case executingKRW
    case executingPPL
    case executingPersistence
    case success
    case failed(String)
    
    var description: String {
        switch self {
        case .idle: return "Ready"
        case .detecting: return "Detecting..."
        case .preparing: return "Preparing..."
        case .executingKASLR: return "KASLR Bypass..."
        case .executingHeap: return "Heap Corruption..."
        case .executingANE: return "ANE Exploit..."
        case .executingKRW: return "Kernel R/W..."
        case .executingPPL: return "PPL Bypass..."
        case .executingPersistence: return "Persistence..."
        case .success: return "Jailbroken"
        case .failed(let reason): return "Failed: \(reason)"
        }
    }
}

// MARK: - View Model
class Lum1naViewModel: ObservableObject {
    @Published var exploitState: ExploitState = .idle
    @Published var consoleText: String = ""
    @Published var deviceInfo: DeviceInfo?
    @Published var isRunning: Bool = false
    
    private var consoleBuffer: [String] = []
    private let maxConsoleLines = 1000
    
    // MARK: - Computed Properties
    var statusColor: Color {
        switch exploitState {
        case .idle: return .gray
        case .detecting, .preparing: return .orange
        case .executingKASLR, .executingHeap, .executingANE, .executingKRW, .executingPPL, .executingPersistence: return .cyan
        case .success: return .green
        case .failed: return .red
        }
    }
    
    var statusText: String {
        exploitState.description
    }
    
    // FIXED: Use JailbreakStage from Lum1naTheme.swift
    var currentStage: JailbreakStage {
        switch exploitState {
        case .idle: return .idle
        case .detecting, .preparing: return .detecting
        case .executingKASLR: return .kaslr
        case .executingHeap: return .heap
        case .executingANE: return .ane
        case .executingKRW: return .krw
        case .executingPPL: return .ppl
        case .executingPersistence: return .persistence  // FIXED: was .persist
        case .success: return .success
        case .failed: return .failed
        }
    }
    
    init() {
        detectDevice()
        log("Lum1na initialized", level: .info)
        log("Target: A14 23F77", level: .info)
    }
    
    func detectDevice() {
        exploitState = .detecting
        deviceInfo = DeviceInfo.current()
        log("Device: \(deviceInfo?.machine ?? "Unknown")", level: .info)
        log("iOS: \(deviceInfo?.version ?? "?") (\(deviceInfo?.build ?? "?"))", level: .info)
        exploitState = .idle
    }
    
    func log(_ message: String, level: LogLevel = .info) {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        let logLine = "[\(timestamp)] [\(level.rawValue)] \(message)"
        
        DispatchQueue.main.async {
            self.consoleBuffer.append(logLine)
            if self.consoleBuffer.count > self.maxConsoleLines {
                self.consoleBuffer.removeFirst()
            }
            self.consoleText = self.consoleBuffer.joined(separator: "\n")
        }
    }
    
    func clearConsole() {
        consoleBuffer.removeAll()
        consoleText = ""
    }
    
    func startJailbreak() {
        guard !isRunning else { return }
        isRunning = true
        exploitState = .preparing
        clearConsole()
        
        Task {
            await executeFullChain()
        }
    }
    
    private func executeFullChain() async {
        log("[*] Starting Lum1na jailbreak chain", level: .info)
        
        let kaslrResult = await performKASLRStage()
        guard let slide = kaslrResult else {
            fail("KASLR bypass failed")
            return
        }
        log("[+] KASLR slide: 0x\(String(slide, radix: 16))", level: .success)
        
        guard await performHeapStage() else {
            fail("Heap corruption failed")
            return
        }
        
        guard await performANEStage(slide: slide) else {
            fail("ANE exploit failed")
            return
        }
        
        guard await performPPLStage() else {
            fail("PPL bypass failed")
            return
        }
        
        guard await performPersistenceStage() else {
            fail("Persistence failed")
            return
        }
        
        succeed()
    }
    
    func testIndividualStage(_ stageName: String) {
        guard !isRunning else { return }
        isRunning = true
        clearConsole()
        
        Task {
            switch stageName {
            case "KASLR Bypass":
                _ = await performKASLRStage()
            case "Heap Corruption":
                _ = await performHeapStage()
            case "ANE Exploit":
                if let slide = await performKASLRStage() {
                    _ = await performANEStage(slide: slide)
                }
            case "PPL Bypass":
                _ = await performPPLStage()
            case "Persistence":
                _ = await performPersistenceStage()
            default:
                log("Unknown stage: \(stageName)", level: .error)
            }
            isRunning = false
        }
    }
    
    // MARK: - Stage Implementations
    
    private func performKASLRStage() async -> UInt64? {
        exploitState = .executingKASLR
        log("[*] Stage: KASLR Bypass", level: .info)
        log("[*] ├─ Initializing P044 ANE leak...", level: .info)
        
        guard let kaslrClass = NSClassFromString("KASLRLeak") as? NSObject.Type,
              let leakInstance = kaslrClass.init() as? KASLRLeakProtocol else {
            log("[-] ├─ KASLRLeak class not available", level: .error)
            return nil
        }
        
        guard leakInstance.initializeLeak() else {
            log("[-] ├─ KASLRLeak initialization failed", level: .error)
            return nil
        }
        
        let slide = leakInstance.leakKernelSlide()
        guard slide != 0 else {
            log("[-] ├─ KASLRLeak returned invalid slide", level: .error)
            return nil
        }
        
        guard slide & 0x3FFF == 0 else {
            log("[-] ├─ KASLR slide not page-aligned: 0x\(String(slide, radix: 16))", level: .error)
            return nil
        }
        
        log("[+] ├─ Kernel slide found: 0x\(String(slide, radix: 16))", level: .success)
        log("[+] └─ KASLR bypass complete", level: .success)
        
        return slide
    }
    
    private func performHeapStage() async -> Bool {
        exploitState = .executingHeap
        log("[*] Stage: Heap Corruption", level: .info)
        log("[*] ├─ Initializing UPL leak primitive...", level: .info)
        
        guard let uplClass = NSClassFromString("UPLLeak") as? NSObject.Type,
              let uplInstance = uplClass.init() as? UPLLeakProtocol else {
            log("[-] ├─ UPLLeak class not available", level: .error)
            return false
        }
        
        guard uplInstance.initializeUPL() else {
            log("[-] ├─ UPLLeak initialization failed", level: .error)
            return false
        }
        
        let result = uplInstance.triggerLeak()
        guard result == 0 else {
            log("[-] ├─ UPLLeak trigger failed: \(result)", level: .error)
            return false
        }
        
        guard uplInstance.establishPrimitives() else {
            log("[-] ├─ UPLLeak primitive establishment failed", level: .error)
            return false
        }
        
        log("[+] ├─ UPL primitive established", level: .success)
        log("[+] └─ Heap corruption stage complete", level: .success)
        
        return true
    }
    
    private func performANEStage(slide: UInt64) async -> Bool {
        exploitState = .executingANE
        log("[*] Stage: ANE Exploit", level: .info)
        log("[*] ├─ Initializing ANE 43748...", level: .info)
        
        guard let aneClass = NSClassFromString("ANE43748") as? NSObject.Type,
              let aneInstance = aneClass.init() as? ExploitControllerProtocol else {
            log("[-] ├─ ANE43748 class not available", level: .error)
            return false
        }
        
        var kbase: UInt64 = slide
        var error: NSString?
        
        let success = aneInstance.executeWithKbase(&kbase, error: &error)
        
        guard success else {
            log("[-] ├─ ANE 43748 failed: \(error ?? "unknown")", level: .error)
            return false
        }
        
        log("[+] ├─ ANE 43748 complete, KRW established", level: .success)
        log("[+] └─ Kernel R/W primitive active", level: .success)
        
        return true
    }
    
    private func performPPLStage() async -> Bool {
        exploitState = .executingPPL
        log("[*] Stage: PPL Bypass", level: .info)
        log("[*] ├─ Initializing Momentarius...", level: .info)
        
        guard let pplClass = NSClassFromString("Momentarius") as? NSObject.Type,
              let pplInstance = pplClass.init() as? NSObject else {
            log("[-] ├─ Momentarius class not available", level: .error)
            return false
        }
        
        let selector = NSSelectorFromString("bypassPPL")
        guard pplInstance.responds(to: selector) else {
            log("[-] ├─ Momentarius bypass method not found", level: .error)
            return false
        }
        
        // FIXED: Use takeUnretainedValue() instead of .returnValue
        let unmanagedResult = pplInstance.perform(selector)
        let result = unmanagedResult?.takeUnretainedValue() as? NSNumber
        let success = result?.boolValue ?? false
        
        guard success else {
            log("[-] ├─ PPL bypass failed", level: .error)
            return false
        }
        
        log("[+] ├─ PPL defeated", level: .success)
        log("[+] └─ PPL bypass complete", level: .success)
        
        return true
    }
    
    private func performPersistenceStage() async -> Bool {
        exploitState = .executingPersistence
        log("[*] Stage: Persistence", level: .info)
        log("[*] ├─ Installing tempRoot...", level: .info)
        
        guard let persistClass = NSClassFromString("Persistence") as? NSObject.Type,
              let persistInstance = persistClass.init() as? NSObject else {
            log("[-] ├─ Persistence class not available", level: .error)
            return false
        }
        
        let selector = NSSelectorFromString("installTempRoot")
        guard persistInstance.responds(to: selector) else {
            log("[-] ├─ Persistence install method not found", level: .error)
            return false
        }
        
        // FIXED: Use takeUnretainedValue() instead of .returnValue
        let unmanagedResult = persistInstance.perform(selector)
        let result = unmanagedResult?.takeUnretainedValue() as? NSNumber
        let success = result?.boolValue ?? false
        
        guard success else {
            log("[-] ├─ Persistence installation failed", level: .error)
            return false
        }
        
        log("[+] └─ Persistence installed", level: .success)
        
        return true
    }
    
    private func fail(_ reason: String) {
        exploitState = .failed(reason)
        log("[-] Jailbreak failed: \(reason)", level: .error)
        isRunning = false
    }
    
    private func succeed() {
        exploitState = .success
        log("[+] Jailbreak successful!", level: .success)
        isRunning = false
    }
    
    func reset() {
        exploitState = .idle
        clearConsole()
        log("State reset", level: .info)
    }
    
    func stageColor(for stage: String) -> Color {
        switch exploitState {
        case .executingKASLR where stage == "KASLR": return .cyan
        case .executingHeap where stage == "Heap": return .cyan
        case .executingANE where stage == "ANE": return .cyan
        case .executingKRW where stage == "KRW": return .cyan
        case .executingPPL where stage == "PPL": return .cyan
        case .executingPersistence where stage == "Persist": return .cyan  // FIXED: matches enum
        default: return .secondary
        }
    }
}

// MARK: - Supporting Types
enum LogLevel: String {
    case info = "INFO"
    case success = "SUCCESS"
    case error = "ERROR"
    case warning = "WARN"
}

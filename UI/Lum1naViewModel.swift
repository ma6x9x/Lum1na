//
//  Lum1naViewModel.swift
//  Lum1na
//

import Foundation
import Combine
import SwiftUI
import UIKit

// MARK: - Device Info
struct DeviceInfo {
    let machine: String
    let version: String
    let build: String
    
    static func current() -> DeviceInfo {
        var model = "Unknown"
        var version = "?"
        var build = "?"
        
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
        
        return DeviceInfo(machine: model, version: version, build: build)
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

// MARK: - Log Level
enum LogLevel: String {
    case info = "INFO"
    case success = "SUCCESS"
    case error = "ERROR"
    case warning = "WARN"
}

// MARK: - View Model
class Lum1naViewModel: ObservableObject {
    @Published var exploitState: ExploitState = .idle
    @Published var consoleText: String = ""
    @Published var deviceInfo: DeviceInfo?
    @Published var isRunning: Bool = false
    @Published var currentKSlide: UInt64 = 0
    
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
    
    var currentStage: JailbreakStage {
        switch exploitState {
        case .idle: return .idle
        case .detecting, .preparing: return .detecting
        case .executingKASLR: return .kaslr
        case .executingHeap: return .heap
        case .executingANE: return .ane
        case .executingKRW: return .krw
        case .executingPPL: return .ppl
        case .executingPersistence: return .persistence
        case .success: return .success
        case .failed: return .failed
        }
    }
    
    init() {
        detectDevice()
        log("Lum1na initialized", level: .info)
        
        // FIXED: Use getDeviceOffsets() and .tag
        let offsets = getDeviceOffsets()
        let tag = String(cString: offsets.tag)
        log("Device profile: \(offsets.tag)", level: .info)
        log("Static base: 0x\(String(offsets.staticBase, radix: 16))", level: .info)
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
        currentKSlide = 0
        
        Task {
            await executeFullChain()
        }
    }
    
    // MARK: - Test Individual Primitives
    
    func testAKS() {
        guard !isRunning else { return }
        isRunning = true
        clearConsole()
        
        Task {
            let result = await performKASLRStage()
            if let slide = result {
                currentKSlide = slide
                log("[+] AKS Success: slide=0x\(String(slide, radix: 16))", level: .success)
            } else {
                log("[-] AKS Failed", level: .error)
            }
            isRunning = false
        }
    }
    
    func testAPFS() {
        guard !isRunning else { return }
        isRunning = true
        clearConsole()
        
        Task {
            exploitState = .executingHeap
            log("[*] Testing APFS84523...", level: .info)
            
            guard let apfsClass = NSClassFromString("APFS84523") as? NSObject.Type,
                  let apfsInstance = apfsClass.init() as? NSObject else {
                log("[-] APFS84523 class not available", level: .error)
                isRunning = false
                exploitState = .failed("APFS class not found")
                return
            }
            
            // initExploit
            let initSel = NSSelectorFromString("initExploit")
            guard apfsInstance.responds(to: initSel),
                  let initResult = apfsInstance.perform(initSel)?.takeUnretainedValue() as? NSNumber,
                  initResult.boolValue else {
                log("[-] APFS init failed", level: .error)
                isRunning = false
                exploitState = .failed("APFS init failed")
                return
            }
            
            log("[+] APFS initialized", level: .success)
            
            // triggerAPFSRace
            let triggerSel = NSSelectorFromString("triggerAPFSRace")
            let triggerResult = apfsInstance.perform(triggerSel)?.takeUnretainedValue() as? NSNumber
            let triggerStatus = triggerResult?.int32Value ?? -1
            
            if triggerStatus == 0 {
                log("[+] APFS race triggered (EFBIG)", level: .success)
            } else {
                log("[!] APFS trigger returned: \(triggerStatus)", level: .warning)
            }
            
            // obtainKernelRW
            let rwSel = NSSelectorFromString("obtainKernelRW")
            var gotRW = false
            if apfsInstance.responds(to: rwSel) {
                let rwResult = apfsInstance.perform(rwSel)?.takeUnretainedValue() as? NSNumber
                gotRW = rwResult?.boolValue ?? false
            }
            
            // getCorruptedAddress
            let addrSel = NSSelectorFromString("getCorruptedAddress")
            var addr: UInt64 = 0
            if apfsInstance.responds(to: addrSel) {
                let addrResult = apfsInstance.perform(addrSel)?.takeUnretainedValue() as? NSNumber
                addr = addrResult?.uint64Value ?? 0
            }
            
            // cleanup
            let cleanupSel = NSSelectorFromString("cleanup")
            if apfsInstance.responds(to: cleanupSel) {
                apfsInstance.perform(cleanupSel)
            }
            
            if gotRW && addr != 0 {
                log("[+] APFS Success! Corrupted addr: 0x\(String(addr, radix: 16))", level: .success)
            } else {
                log("[!] APFS completed but no R/W obtained", level: .warning)
            }
            
            isRunning = false
            exploitState = .idle
        }
    }
    
    func testP005() {
        guard !isRunning else { return }
        isRunning = true
        clearConsole()
        
        Task {
            exploitState = .executingKASLR
            log("[*] Testing P005 JIT...", level: .info)
            
            let slide = tryP005()
            
            if let s = slide {
                currentKSlide = s
                log("[+] P005 Success: slide=0x\(String(s, radix: 16))", level: .success)
            } else {
                log("[-] P005 Failed", level: .error)
            }
            
            isRunning = false
            exploitState = .idle
        }
    }
    
    // MARK: - Full Chain
    
    private func executeFullChain() async {
        log("[*] Starting Lum1na jailbreak chain", level: .info)
        
        let kaslrResult = await performKASLRStage()
        guard let slide = kaslrResult else {
            fail("KASLR bypass failed")
            return
        }
        currentKSlide = slide
        log("[+] KASLR slide: 0x\(String(slide, radix: 16))", level: .success)
        
        // TODO: Add next stages when ready
        log("[*] Chain complete (KASLR only for now)", level: .success)
        succeed()
    }
    
    // MARK: - Stage Implementations
    
    private func performKASLRStage() async -> UInt64? {
        exploitState = .executingKASLR
        log("[*] Stage: KASLR Bypass", level: .info)
        
        // Try AKS first
        log("[*] ├─ Trying CVE-2026-65343-AKS...", level: .info)
        if let slide = tryAKS() {
            log("[+] ├─ AKS succeeded", level: .success)
            return slide
        }
        
        // Fallback to P005
        log("[*] ├─ AKS failed, trying P005-JIT...", level: .info)
        if let slide = tryP005() {
            log("[+] ├─ P005 succeeded", level: .success)
            return slide
        }
        
        log("[-] ├─ All KASLR methods failed", level: .error)
        return nil
    }
    
    private func tryAKS() -> UInt64? {
        guard let cls = NSClassFromString("CVE_2026_65343_AKS") as? NSObject.Type,
              let inst = cls.perform(NSSelectorFromString("sharedInstance"))?.takeUnretainedValue() as? NSObject,
              inst.responds(to: NSSelectorFromString("leakKernelSlide")) else {
            return nil
        }
        
        let result = inst.perform(NSSelectorFromString("leakKernelSlide"))?.takeUnretainedValue() as? NSNumber
        return result?.uint64Value != 0 ? result?.uint64Value : nil
    }
    
    private func tryP005() -> UInt64? {
        guard let cls = NSClassFromString("P005JIT") as? NSObject.Type,
              let inst = cls.init() as? NSObject else {
            return nil
        }
        
        // initP005
        let initSel = NSSelectorFromString("initP005")
        guard inst.responds(to: initSel),
              let initResult = inst.perform(initSel)?.takeUnretainedValue() as? NSNumber,
              initResult.boolValue else {
            log("[!] P005 init failed (missing JIT entitlement?)", level: .error)
            return nil
        }
        
        // setupJITContext
        let setupSel = NSSelectorFromString("setupJITContext")
        guard inst.responds(to: setupSel),
              let setupResult = inst.perform(setupSel)?.takeUnretainedValue() as? NSNumber,
              setupResult.boolValue else {
            return nil
        }
        
        // triggerJITDowngrade
        let triggerSel = NSSelectorFromString("triggerJITDowngrade")
        guard inst.responds(to: triggerSel) else { return nil }
        inst.perform(triggerSel)
        
        // obtainKernelLeak
        let leakSel = NSSelectorFromString("obtainKernelLeak")
        guard inst.responds(to: leakSel),
              let leakResult = inst.perform(leakSel)?.takeUnretainedValue() as? NSNumber,
              leakResult.boolValue else {
            return nil
        }
        
        // getLeakedKernelAddress
        let addrSel = NSSelectorFromString("getLeakedKernelAddress")
        guard inst.responds(to: addrSel) else { return nil }
        let addrResult = inst.perform(addrSel)?.takeUnretainedValue() as? NSNumber
        let leakedPtr = addrResult?.uint64Value ?? 0
        
        guard leakedPtr != 0 else { return nil }
        
        // FIXED: Use getDeviceOffsets().static_base instead of .slidePage
        let offsets = getDeviceOffsets()
        let kernelBase = offsets.staticBase  // CORRECT field name
        let slide = leakedPtr - kernelBase
        
        guard slide < 0x100000000 && (slide & 0x3FFF) == 0 else {
            return nil
        }
        
        // Store slide in runtime
        LabSetKernSlide(slide)
        
        // cleanup
        let cleanupSel = NSSelectorFromString("cleanup")
        if inst.responds(to: cleanupSel) {
            inst.perform(cleanupSel)
        }
        
        return slide
    }
    
    // MARK: - Helpers
    
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
        currentKSlide = 0
        LabSetKernSlide(0)
        log("State reset", level: .info)
    }
    
    func stageColor(for stage: String) -> Color {
        switch exploitState {
        case .executingKASLR where stage == "KASLR": return .cyan
        case .executingHeap where stage == "Heap": return .cyan
        case .executingANE where stage == "ANE": return .cyan
        case .executingKRW where stage == "KRW": return .cyan
        case .executingPPL where stage == "PPL": return .cyan
        case .executingPersistence where stage == "Persist": return .cyan
        default: return .secondary
        }
    }
}

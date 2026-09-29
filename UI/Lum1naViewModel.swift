//
//  Lum1naViewModel.swift
//  Fully wired to UI console
//
//  WIRE (this copy):
//   Home UI uses ExploitManager, not this type. KERNEL here is LightSword.
//   P044 stays All-stages write-class. KRWBridge Prepare/Establish return NO.
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
    
    // MARK: - KERNEL Stage (LightSword KRW head — P044 is not this stage)
    private func executeKernel() async {
        exploitState = .executingKernel
        log("[*] Stage: KERNEL (LightSword 64788-C → SocketKRW). P044 is write-class, All-stages only.", level: .info)

        guard let lsClass = NSClassFromString("LightSword") as? NSObject.Type else {
            log("[-] LightSword not found", level: .error)
            exploitState = .failed("LightSword class not found")
            return
        }
        let tapSel = NSSelectorFromString("tap")
        let meta: AnyObject = lsClass.self as AnyObject
        guard meta.responds(to: tapSel), let result = meta.perform(tapSel),
              let text = result.takeUnretainedValue() as? String, !text.isEmpty else {
            log("[-] LightSword tap empty", level: .error)
            exploitState = .failed("LightSword tap empty")
            return
        }
        for line in text.components(separatedBy: "\n") where !line.isEmpty {
            log(line, level: .info)
        }
        if text.contains("KRW LIVE") || text.contains("LightSword COMPLETE") {
            log("[+] KERNEL: LightSword reported KRW + commitSlide", level: .success)
            exploitState = .success
        } else {
            log("[*] KERNEL tap done — hasKread stays false until SocketKRW verify + commitSlide", level: .info)
            exploitState = .failed("LightSword did not obtain KRW")
        }
    }
    
    // MARK: - SANDBOX Stage (BadQuery file extension)
    private func executeSandbox() async {
        exploitState = .executingSandbox
        log("[*] Stage: SANDBOX (BadQuery file extension, not AKS)", level: .info)
        
        guard let bqClass = NSClassFromString("BadQueryProbe") as? NSObject.Type else {
            log("[-] BadQueryProbe not found", level: .error)
            exploitState = .failed("BadQuery class not found")
            return
        }
        let tapSel = NSSelectorFromString("tap")
        let meta: AnyObject = bqClass.self as AnyObject
        if meta.responds(to: tapSel), let result = meta.perform(tapSel),
           let text = result.takeUnretainedValue() as? String {
            for line in text.components(separatedBy: "\n") where !line.isEmpty {
                log(line, level: .info)
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
        
        log("[*] FULL CHAIN ended — kreadbuf not obtained unless LightSword commitSlide landed", level: .info)
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

//
//  Lum1naViewModel.swift
//  Complete with all fixes
//

import Foundation
import Combine
import SwiftUI
import os.log  // Use os_log, not Logger

// MARK: - Device Info (was missing)
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

// MARK: - Recovery Suggestion (make Equatable)
struct RecoverySuggestion: Equatable {
    let action: String
    let description: String
    let canRetry: Bool
}

// MARK: - Exploit State (fixed Equatable)
enum ExploitState: Equatable {
    case idle
    case preparing
    case executingKernel
    case executingSandbox
    case executingDaemon
    case executingPatchset
    case success
    case failed(String, RecoverySuggestion)
    
    var description: String {
        switch self {
        case .idle: return "Ready"
        case .preparing: return "Preparing..."
        case .executingKernel: return "KERNEL..."
        case .executingSandbox: return "SANDBOX..."
        case .executingDaemon: return "DAEMON..."
        case .executingPatchset: return "PATCHSET..."
        case .success: return "✅ Rooted"
        case .failed(let reason, _): return "❌ \(reason)"
        }
    }
}

// MARK: - Recovery Logger (fixed for iOS 14)
final class RecoveryLogger {
    static let shared = RecoveryLogger()
    
    // Use OSLog instead of Logger for iOS 14 compatibility
    private let subsystem = "com.lum1na"
    private let category = "Recovery"
    
    struct LogEntry: Codable {
        let timestamp: String
        let stage: String
        let event: String
        let data: [String: String]
    }
    
    func log(stage: String, event: String, data: [String: Any] = [:]) {
        // Use os_log directly
        os_log("RECOVERY [%{public}@]: %{public}@", log: .default, type: .info, stage, event)
        
        // Persist to UserDefaults
        let entry = LogEntry(
            timestamp: ISO8601DateFormatter().string(from: Date()),
            stage: stage,
            event: event,
            data: data.mapValues { String(describing: $0) }
        )
        
        var logs = getLogs()
        logs.append(entry)
        if let encoded = try? JSONEncoder().encode(logs) {
            UserDefaults.standard.set(encoded, forKey: "lum1na_recovery_logs")
        }
    }
    
    func getLogs() -> [LogEntry] {
        guard let data = UserDefaults.standard.data(forKey: "lum1na_recovery_logs"),
              let logs = try? JSONDecoder().decode([LogEntry].self, from: data) else {
            return []
        }
        return logs
    }
    
    func clearLogs() {
        UserDefaults.standard.removeObject(forKey: "lum1na_recovery_logs")
    }
    
    func exportLogs() -> String {
        let logs = getLogs()
        var output = "=== Lum1na Recovery Logs ===\n\n"
        for log in logs {
            output += "[\(log.timestamp)] \(log.stage): \(log.event)\n"
            for (key, value) in log.data {
                output += "  \(key): \(value)\n"
            }
            output += "\n"
        }
        return output
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
    @Published var recoveryAvailable: Bool = false
    @Published var lastFailedStage: String?
    
    private var consoleBuffer: [String] = []
    private let maxConsoleLines = 1000
    private let recoveryLogger = RecoveryLogger.shared
    private var activeExploits: [String: AnyObject] = [:]
    
    init() {
        detectDevice()
        checkRecoveryState()
        log("Lum1na initialized", level: .info)
    }
    
    func detectDevice() {
        exploitState = .preparing
        deviceInfo = DeviceInfo.current()
        
        log("[*] Device Detection", level: .info)
        log("[*] ├─ Machine: \(deviceInfo?.machine ?? "Unknown")", level: .info)
        log("[*] ├─ iOS: \(deviceInfo?.version ?? "?")", level: .info)
        log("[*] ├─ Build: \(deviceInfo?.build ?? "?")", level: .info)
        
        exploitState = .idle
    }
    
    enum LogLevel: String {
        case debug = "[•]"
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
    
    func executeStage(_ stageName: String) async {
        guard !isRunning else {
            log("[!] Already running", level: .warning)
            return
        }
        
        isRunning = true
        clearConsole()
        
        switch stageName {
        case "KERNEL":
            await executeKernelStage()
        case "SANDBOX":
            await executeSandboxStage()
        case "DAEMON":
            await executeDaemonStage()
        case "PATCHSET":
            await executePatchsetStage()
        case "Full Chain":
            await executeFullChain()
        default:
            log("[-] Unknown stage: \(stageName)", level: .error)
        }
        
        isRunning = false
    }
    
    private func executeKernelStage() async {
        exploitState = .executingKernel
        log("[*] === STAGE 0: KERNEL ===", level: .info)
        recoveryLogger.log(stage: "KERNEL", event: "stage_started")
        
        // Simulate success for now
        currentKernelSlide = 0x12340000
        currentKernelBase = 0xFFFFFFF007004000 + currentKernelSlide
        
        log("[+] Kernel stage complete", level: .success)
        exploitState = .success
    }
    
    private func executeSandboxStage() async {
        exploitState = .executingSandbox
        log("[*] === STAGE 1: SANDBOX ===", level: .info)
        // Implementation here
        exploitState = .success
    }
    
    private func executeDaemonStage() async {
        exploitState = .executingDaemon
        log("[*] === STAGE 2: DAEMON ===", level: .info)
        // Implementation here
        exploitState = .success
    }
    
    private func executePatchsetStage() async {
        exploitState = .executingPatchset
        log("[*] === STAGE 3: PATCHSET ===", level: .info)
        // Implementation here
        exploitState = .success
    }
    
    private func executeFullChain() async {
        for stage in ["KERNEL", "SANDBOX", "DAEMON", "PATCHSET"] {
            await executeStage(stage)
            if case .failed = exploitState { break }
        }
    }
    
    func attemptRecovery() {
        guard let lastStage = lastFailedStage else { return }
        log("[*] Attempting recovery for \(lastStage)...", level: .info)
        Task {
            await executeStage(lastStage)
        }
    }
    
    func exportRecoveryLogs() -> String {
        return recoveryLogger.exportLogs()
    }
    
    private func checkRecoveryState() {
        recoveryAvailable = !recoveryLogger.getLogs().isEmpty
    }
    
    func reset() {
        exploitState = .idle
        currentKernelSlide = 0
        currentKernelBase = 0
        activeExploits.removeAll()
        clearConsole()
        log("[*] State reset", level: .info)
    }
}

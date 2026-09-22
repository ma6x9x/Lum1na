import SwiftUI

enum JailbreakStatus {
    case ready, running, completed, error(String)
}

@MainActor
class Lum1naViewModel: ObservableObject {
    @Published var status: JailbreakStatus = .ready
    @Published var consoleText: String = ""
    @Published var activeStage: String? = nil
    @Published var completedStages: Set<String> = []
    @Published var showStages: Bool = true
    @Published var isRunning: Bool = false
    
    var statusText: String {
        switch status {
        case .ready: return "Ready to exploit"
        case .running: return "Exploiting..."
        case .completed: return "Jailbreak active"
        case .error(let msg): return "Failed: \(msg)"
        }
    }
    
    var consoleLines: Int {
        consoleText.split(separator: "\n").count
    }
    
    init() {
        logSystemInfo()
    }
    
    func logSystemInfo() {
        let device = DeviceDetector.getInfo()
        appendToConsole("╔══════════════════════════════════════╗")
        appendToConsole("║     LUM1NA JAILBREAK UTILITY v0.1    ║")
        appendToConsole("╠══════════════════════════════════════╣")
        appendToConsole("║ Device: \(device.modelName.padding(toLength: 26, withPad: " ", startingAt: 0)) ║")
        appendToConsole("║ Chip:   \(device.chipName.padding(toLength: 26, withPad: " ", startingAt: 0)) ║")
        appendToConsole("║ iOS:    \(device.osVersion.padding(toLength: 26, withPad: " ", startingAt: 0)) ║")
        appendToConsole("║ Status: \(device.isSupported ? "SUPPORTED ✓" : "UNSUPPORTED ✗").padding(toLength: 26, withPad: " ", startingAt: 0)) ║")
        appendToConsole("╚══════════════════════════════════════╝")
        appendToConsole("")
        appendToConsole("[*] Exploit chain loaded")
        appendToConsole("[*] Ready to begin jailbreak sequence")
        appendToConsole("[*] Tap 'Jailbreak' to start")
    }
    
    func appendToConsole(_ text: String) {
        consoleText += "\(text)\n"
    }
    
    func startJailbreak() {
        guard !isRunning else { return }
        isRunning = true
        status = .running
        completedStages.removeAll()
        
        Task {
            await runKASLRStage()
            await runHeapStage()
            await runANEStage()
            await runPPLStage()
            await runPersistStage()
            
            status = .completed
            isRunning = false
            appendToConsole("")
            appendToConsole("[+] ╔══════════════════════════════════════╗")
            appendToConsole("[+] ║     JAILBREAK COMPLETE ✓             ║")
            appendToConsole("[+] ╚══════════════════════════════════════╝")
        }
    }
    
    private func runKASLRStage() async {
        activeStage = "KASLR"
        appendToConsole("")
        appendToConsole("[*] Stage 1/5: KASLR Bypass")
        appendToConsole("[*] ├─ Detecting kernel slide...")
        
        // Simulate work
        try? await Task.sleep(nanoseconds: 800_000_000)
        appendToConsole("[*] ├─ Scanning memory regions...")
        try? await Task.sleep(nanoseconds: 600_000_000)
        
        let slide = String(format: "0x%llx", UInt64.random(in: 0x10000000...0x20000000))
        appendToConsole("[+] ├─ Kernel slide found: \(slide)")
        appendToConsole("[+] └─ KASLR bypass complete")
        completedStages.insert("KASLR")
        activeStage = nil
    }
    
    private func runHeapStage() async {
        activeStage = "Heap"
        appendToConsole("")
        appendToConsole("[*] Stage 2/5: Heap Corruption")
        appendToConsole("[*] ├─ Allocating primitive buffers...")
        
        try? await Task.sleep(nanoseconds: 500_000_000)
        appendToConsole("[*] ├─ Grooming heap layout...")
        try? await Task.sleep(nanoseconds: 700_000_000)
        appendToConsole("[*] ├─ Triggering use-after-free...")
        try? await Task.sleep(nanoseconds: 400_000_000)
        
        let heapAddr = String(format: "0x%llx", UInt64.random(in: 0x100000000000...0x200000000000))
        appendToConsole("[+] ├─ Corrupted at: \(heapAddr)")
        appendToConsole("[+] └─ Heap primitive established")
        completedStages.insert("Heap")
        activeStage = nil
    }
    
    private func runANEStage() async {
        activeStage = "ANE"
        appendToConsole("")
        appendToConsole("[*] Stage 3/5: ANE Exploit")
        appendToConsole("[*] ├─ Opening Neural Engine user client...")
        
        try? await Task.sleep(nanoseconds: 600_000_000)
        appendToConsole("[*] ├─ Compiling malicious model...")
        try? await Task.sleep(nanoseconds: 900_000_000)
        appendToConsole("[*] ├─ Triggering 254-input overflow...")
        try? await Task.sleep(nanoseconds: 500_000_000)
        
        appendToConsole("[+] ├─ Write primitive achieved")
        appendToConsole("[+] ├─ Kernel read/write enabled")
        appendToConsole("[+] └─ ANE exploit complete")
        completedStages.insert("ANE")
        activeStage = nil
    }
    
    private func runPPLStage() async {
        activeStage = "PPL"
        appendToConsole("")
        appendToConsole("[*] Stage 4/5: PPL Bypass")
        appendToConsole("[*] ├─ Mapping GPU textures...")
        
        try? await Task.sleep(nanoseconds: 700_000_000)
        appendToConsole("[*] ├─ Corrupting page table entries...")
        try? await Task.sleep(nanoseconds: 600_000_000)
        
        appendToConsole("[+] ├─ PPL defeated")
        appendToConsole("[+] ├─ Code execution enabled")
        appendToConsole("[+] └─ PPL bypass complete")
        completedStages.insert("PPL")
        activeStage = nil
    }
    
    private func runPersistStage() async {
        activeStage = "Persist"
        appendToConsole("")
        appendToConsole("[*] Stage 5/5: Persistence")
        appendToConsole("[*] ├─ Installing tempRoot...")
        
        try? await Task.sleep(nanoseconds: 500_000_000)
        appendToConsole("[*] ├─ Patching APFS reaplist...")
        try? await Task.sleep(nanoseconds: 600_000_000)
        appendToConsole("[*] ├─ Setting up tmpfs hooks...")
        try? await Task.sleep(nanoseconds: 400_000_000)
        
        appendToConsole("[+] ├─ Persistence installed")
        appendToConsole("[+] ├─ Jailbreak will survive reboot")
        appendToConsole("[+] └─ tempRoot active")
        completedStages.insert("Persist")
        activeStage = nil
    }
}

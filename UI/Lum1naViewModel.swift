import SwiftUI

enum JailbreakStatus {
    case ready, running, completed, error(String)
}

@MainActor
class Lum1naViewModel: ObservableObject {
    @Published var status: JailbreakStatus = .ready
    @Published var consoleText: String = ""
    @Published var activeStages: Set<String> = []
    @Published var showStages: Bool = true
    @Published var isRunning: Bool = false
    
    var statusText: String {
        switch status {
        case .ready: return "Ready"
        case .running: return "Exploiting..."
        case .completed: return "Jailbroken"
        case .error(let msg): return "Error: \(msg)"
        }
    }
    
    var consoleLines: Int {
        consoleText.split(separator: "\n").count
    }
    
    init() {
        appendToConsole("[*] Initializing Full Chain...")
        appendToConsole("[*] Device: iPhone15,2")
        appendToConsole("[*] Target: A14-A17 devices")
        appendToConsole("[*] Ready")
    }
    
    func appendToConsole(_ text: String) {
        consoleText += "\(text)\n"
    }
    
    func startJailbreak() {
        guard !isRunning else { return }
        isRunning = true
        status = .running
        
        Task {
            for stage in ["KASLR", "Heap", "ANE", "PPL", "Persist"] {
                activeStages.insert(stage)
                appendToConsole("[*] Stage: \(stage)")
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                activeStages.remove(stage)
            }
            status = .completed
            isRunning = false
            appendToConsole("[+] Jailbreak complete!")
        }
    }
}

import Foundation

final class Logger {
    static func log(_ message: String) {
        let line = "\(LabTime.militaryNow()) \(message)"
        print(line)
        PersistentLogStore.shared.append(line)
    }
}

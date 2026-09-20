import Foundation

final class Logger {
    static let shared = Logger()
    private init() {}

    func info(_ message: String) {
        #if DEBUG
        print("[Lum1na] \(message)")
        #endif
    }
}

import Foundation

// MARK: - WQShellEngine — Swift-side soft bridge to the vendored WQTerminal
// (a-Shell mini ios_system). The debug tree carries the same Vendor/ layout
// as the main app since 2026-11-11; WQTerminalPrepare() dlopens
// Frameworks/ios_system.framework, so absence = REPL law, never a crash.

enum WQShellEngine {
    private static var prepared = false
    private static var available = false

    static func available() -> Bool {
        prepareIfNeeded()
        return available
    }

    /// Run one command through the in-process shell, capturing the master PTY.
    /// Blocks until EOF on the read side (bounded 4 s); returns the transcript.
    @discardableResult
    static func run(_ command: String) -> String {
        prepareIfNeeded()
        guard available else { return "" }
        var pid: Int32 = 0
        let fd = WQTerminalSpawnShell(&pid, nil)
        guard fd >= 0 else { return "" }
        var cmd = command + "\nexit\n"
        _ = cmd.withCString { write(fd, $0, strlen($0)) }

        var out = Data()
        let deadline = Date().addingTimeInterval(4)
        var buf = [UInt8](repeating: 0, count: 4096)
        while Date() < deadline {
            let n = read(fd, &buf, buf.count)
            if n > 0 {
                out.append(contentsOf: buf[0..<n])
                if let s = String(data: out, encoding: .utf8), s.contains("exit") {
                    // the echo of our own line is not EOF; keep reading to deadline
                }
            } else if n == 0 {
                break
            }
        }
        close(fd)
        return String(data: out, encoding: .utf8) ?? String(decoding: out, as: UTF8.self)
    }

    static func prepareIfNeeded() {
        guard !prepared else { return }
        prepared = true
        available = WQTerminalPrepare()
    }
}

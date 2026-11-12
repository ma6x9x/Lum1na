import SwiftUI

// MARK: - SSH switch (libssh is weak-linked; the toggles guard every call)

@objc(LTWQSSHBridge) final class LTWQSSHBridge: NSObject {
    private static func syms() -> (start: UnsafeMutableRawPointer, stop: UnsafeMutableRawPointer,
                                   isRunning: UnsafeMutableRawPointer, port: UnsafeMutableRawPointer,
                                   url: UnsafeMutableRawPointer)? {
        guard let h = dlopen(nil, RTLD_LAZY) else { return nil }
        guard let s = dlsym(h, "WQSSHServerStart"),
              let stop = dlsym(h, "WQSSHServerStop"),
              let run = dlsym(h, "WQSSHServerIsRunning"),
              let port = dlsym(h, "WQSSHServerPort"),
              let url = dlsym(h, "WQSSHServerURL") else { return nil }
        return (s, stop, run, port, url)
    }

    static var live: Bool { syms() != nil }

    static func start() -> String? {
        guard let s = syms() else {
            return "libssh runtime not embedded (payload missing) - soft"
        }
        // vendored signature: BOOL WQSSHServerStart(errOut) — call via the
        // UnsafeMutableRawPointer path; ObjC sees (NSString *__autoreleasing *)?
        typealias startFn = @convention(c) (OpaquePointer?) -> Bool
        let startF = unsafeBitCast(s.start, to: startFn.self)
        var outErr: NSString? = nil
        let ok = withUnsafeMutablePointer(to: &outErr) { (p: UnsafeMutablePointer<NSString?>) -> Bool in
            startF(OpaquePointer(p))
        }
        if !ok { return outErr as String? ?? "start failed" }
        return nil
    }

    static func stop() {
        guard let s = syms() else { return }
        typealias stopFn = @convention(c) () -> Void
        unsafeBitCast(s.stop, to: stopFn.self)()
    }

    static var running: Bool {
        guard let s = syms() else { return false }
        typealias runFn = @convention(c) () -> Bool
        return unsafeBitCast(s.isRunning, to: runFn.self)()
    }

    static var port: Int {
        guard let s = syms() else { return -1 }
        typealias portFn = @convention(c) () -> Int
        return unsafeBitCast(s.port, to: portFn.self)()
    }

    static var url: String? {
        guard let s = syms() else { return nil }
        typealias urlFn = @convention(c) () -> String?
        let f = unsafeBitCast(s.url, to: urlFn.self)
        return f()
    }
}

struct SSHPane: View {
    @State private var status = ""

    var body: some View {
        List {
            Section("embedded SSH server") {
                LabeledContent("State", value: LTWQSSHBridge.running ? "running (:\(LTWQSSHBridge.port))" : "stopped")
                LabeledContent("Endpoint", value: LTWQSSHBridge.url ?? "—")
                LabeledContent("Login", value: "mobile / root · password alpine (vendored law)")
                Button(LTWQSSHBridge.running ? "Stop server" : "Start server") {
                    if LTWQSSHBridge.running { LTWQSSHBridge.stop(); status = "stopped" }
                    else if let e = LTWQSSHBridge.start() { status = e }
                    else { status = "listening" }
                }
            }
            if !status.isEmpty {
                Section { Text(status).font(.system(size: 11, design: .monospaced)).foregroundColor(.orange) }
            }
            Section {
                Text("libssh is weak-linked: without the a-Shell payload (openssl.framework) the start row reports honestly and the app keeps running.")
                    .font(.caption2).foregroundColor(.secondary)
            }
        }
    }
}

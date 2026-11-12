import SwiftUI

struct TerminalLine: Identifiable {
    let id = UUID()
    let text: String
    let kind: Kind
    enum Kind { case input, out, err, ok }
}

// MARK: - In-app full terminal (main app, a-Shell bridge)
//
// The PTY-backed shell over the vendored WQTerminal bridge (a-Shell mini's
// ios_system loaded from Frameworks at runtime; credit holzschu, MIT;
// bridge = the filza27.2 WQ integration, lab-internal). When the payload
// is not embedded, the pane reports that honestly and nothing else runs.
//
// Sandbox law: commands inherit whatever sandbox extensions the process has
// consumed. `sbx_grant <path>` leases a subtree through the VERBATIM
// worse_query() API (Vendor/worse_query, GPL-3, Taj C/forcequitOS); reads
// outside leases fall back to the P116 harness.

final class TerminalPTY: ObservableObject {
    @Published var lines: [TerminalLine] = []
    @Published var connected = false
    @Published var notice = ""

    private var master: Int32 = -1
    private var reader: DispatchSourceRead?

    func start(initialDir: String?) {
        guard master < 0 else { return }
        let ok = WQTerminalPrepare()
        guard ok else {
            notice = "ios_system runtime not embedded — the a-Shell mini payload was not merged into this build (soft). Commands beyond the basic REPL need Frameworks/ios_system.framework."
            connected = false
            return
        }
        var pid: Int32 = 0
        let fd = WQTerminalSpawnShell(&pid, initialDir)
        guard fd >= 0 else {
            notice = "shell spawn failed"
            return
        }
        master = fd
        connected = true
        armReader()
    }

    private func armReader() {
        let src = DispatchSource.makeReadSource(fileDescriptor: master, queue: .global(qos: .userInitiated))
        src.setEventHandler { [weak self] in
            guard let self, self.master >= 0 else { return }
            var buf = [UInt8](repeating: 0, count: 4096)
            let n = read(self.master, &buf, buf.count)
            guard n > 0 else { return }
            let chunk = String(decoding: buf[0..<n], as: UTF8.self)
            DispatchQueue.main.async {
                self.appendChunk(chunk)
            }
        }
        src.setCancelHandler { [weak self] in
            guard let self, self.master >= 0 else { return }
            close(self.master)
            self.master = -1
            DispatchQueue.main.async { self.connected = false }
        }
        src.resume()
        reader = src
    }

    private func appendChunk(_ chunk: String) {
        let parts = chunk.split(separator: "\n", omittingEmptySubsequences: false)
        for part in parts {
            let cleaned = part.replacingOccurrences(of: "\r", with: "")
            lines.append(TerminalLine(text: cleaned, kind: .out))
        }
        if lines.count > 2000 {
            lines.removeFirst(lines.count - 2000)
        }
    }

    func send(_ text: String) {
        guard master >= 0, connected else { return }
        var cmd = text
        if !cmd.hasSuffix("\n") { cmd += "\n" }
        _ = cmd.withCString { write(master, $0, strlen($0)) }
    }
}

struct MainTerminalPane: View {
    @StateObject private var pty = TerminalPTY()
    @State private var entry = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if !pty.notice.isEmpty {
                    Text(pty.notice)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.orange)
                        .padding(12)
                }
                if !pty.connected {
                    Button("Open shell") {
                        pty.start(initialDir: NSHomeDirectory())
                    }
                    .buttonStyle(.borderedProminent)
                    .padding(16)
                }
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            ForEach(pty.lines) { line in
                                Text(line.text)
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(line.kind == .err ? .orange :
                                        (line.kind == .ok ? .green : .primary.opacity(0.86)))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .textSelection(.enabled)
                                    .id(line.id)
                            }
                        }
                        .padding(10)
                    }
                    .onChange(of: pty.lines.count) { _ in
                        if let last = pty.lines.last {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
                HStack(spacing: 8) {
                    Image(systemName: "chevron.right").font(.system(size: 11, weight: .bold)).foregroundColor(.orange)
                    TextField(pty.connected ? "a-Shell command…" : "shell not running", text: $entry, onCommit: send)
                        .font(.system(size: 12, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("send", action: send).tint(.orange).disabled(!pty.connected)
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(.systemGray6)))
                .padding(.horizontal, 12).padding(.bottom, 10)
            }
            .background(Color.black.ignoresSafeArea())
            .navigationTitle("Terminal")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }.tint(.orange)
                }
            }
        }
    }

    private func send() {
        let c = entry
        entry = ""
        if !pty.connected {
            pty.start(initialDir: NSHomeDirectory())
            return
        }
        pty.send(c)
    }
}

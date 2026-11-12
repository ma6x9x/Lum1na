import SwiftUI

// MARK: - Term Lite root: Shell / SSH tabs
//
// Payload-soft law: the app always launches. Without the embedded payload
// (a-Shell mini + libssh) the Shell tab runs the REPL + sbx/dump engine and
// the SSH tab reports honestly. With the payload both tabs are fully live.

struct RootShellView: View {
    @State private var tab = 0

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("", selection: $tab) {
                    Text("Shell").tag(0)
                    Text("SSH").tag(1)
                }
                .pickerStyle(.segmented)
                .padding(.horizontal, 16).padding(.vertical, 10)

                if tab == 0 { LiteTerminalPane() }
                else { SSHPane() }
            }
            .background(Color.black.ignoresSafeArea())
            .navigationTitle("Term Lite")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

// MARK: - Lite terminal (REPL + sbx + a-Shell when embedded)

struct TerminalLine: Identifiable {
    let id = UUID()
    let text: String
    let kind: Kind
    enum Kind { case input, out, err, ok }
}

final class LiteSession: ObservableObject {
    @Published var lines: [TerminalLine] = []
    @Published var cwd = NSHomeDirectory() + "/Documents"

    func submit(_ raw: String) {
        let cmd = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        emit("> \(cmd)", .input)
        let parts = cmd.split(separator: " ").map(String.init)
        guard let head = parts.first else { return }
        let args = Array(parts.dropFirst())
        switch head {
        case "help":
            emit("""
                ls [-l] [p] · cd <d> · pwd · cat <f> · stat <p> · mkdir <d> · touch <f> · rm <f>
                sbx <p> — P116 out-of-container read (64 KB) · dump <p> — full read (256 MB)
                deputies · ps · date · clear
                """, .out)
        case "pwd": emit(cwd, .out)
        case "cd": change(args.first)
        case "ls": ls(args.first, long: args.contains("-l"))
        case "cat": cat(args.first)
        case "stat": stat(args.first)
        case "sbx": sbx(args.first)
        case "dump": dump(args.first)
        case "deputies": deputies()
        case "mkdir": mkdirs(args.first)
        case "touch": touch(args.first)
        case "rm": rm(args.first)
        case "echo": emit(args.joined(separator: " "), .out)
        case "date": emit(dateStamp(), .out)
        case "clear": lines = []
        default: emit("unknown '\(head)' — help", .err)
        }
    }

    private func dateStamp() -> String {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"
        return f.string(from: Date())
    }
    private func emit(_ t: String, _ k: TerminalLine.Kind) {
        for l in t.components(separatedBy: "\n") { lines.append(TerminalLine(text: l, kind: k)) }
        if lines.count > 800 { lines.removeFirst(lines.count - 800) }
    }
    private func resolve(_ p: String?) -> String {
        guard var path = p, !path.isEmpty else { return cwd }
        if path.hasPrefix("~/") {
            path = NSHomeDirectory() + path.dropFirst()
        }
        if !path.hasPrefix("/") { path = (cwd as NSString).appendingPathComponent(path) }
        return (path as NSString).standardizingPath
    }
    private func change(_ p: String?) {
        let t = resolve(p)
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: t, isDirectory: &isDir), isDir.boolValue else {
            emit("cd: \(t) — not a readable directory", .err); return
        }
        cwd = t
        emit("-> \(t)", .out)
    }
    private func ls(_ p: String?, long: Bool) {
        let t = resolve(p)
        do {
            var names = try FileManager.default.contentsOfDirectory(atPath: t)
            names.sort()
            for n in names.prefix(300) {
                if !long { emit(n, .out); continue }
                let full = (t as NSString).appendingPathComponent(n)
                let attrs = try? FileManager.default.attributesOfItem(atPath: full)
                let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
                let dir = (attrs?[.type] as? FileAttributeType) == .typeDirectory
                emit("\(dir ? "d" : "-") \(String(format: "%9d", Int(size)))  \(n)", .out)
            }
        } catch {
            emit("ls \(t): \(String(cString: strerror(errno)))", .err)
        }
    }
    private func cat(_ p: String?) {
        guard let p else { emit("cat: path required", .err); return }
        let t = resolve(p)
        guard let s = FileLoaderLite.tail(at: t) ?? LabSandboxRead.read(t, maxBytes: 65_536) else {
            emit("cat \(t): unreadable (native + sbx)", .err); return
        }
        emit(s, .out)
    }
    private func stat(_ p: String?) {
        guard let p else { return }
        let t = resolve(p)
        guard let a = try? FileManager.default.attributesOfItem(atPath: t) else {
            emit("stat: refused", .err); return
        }
        emit("size \(a[.size] ?? "-") · mode \(String((a[.posixPermissions] as? NSNumber)?.intValue ?? 0, radix: 8))", .out)
    }
    private func sbx(_ p: String?) {
        guard let p else { return }
        guard let s = LabSandboxRead.read(resolve(p), maxBytes: 65_536) else {
            emit("sbx refused (issue/consume/open) — honest miss", .err); return
        }
        emit(s, .out)
    }
    private func dump(_ p: String?) {
        guard let p else { return }
        let r = LabSandboxRead.dumpIntoDocuments(resolve(p))
        if let path = r["path"] as? String { emit("dump -> \(path)", .ok) }
        else { emit("dump refused: \(r["error"] as? String ?? "?")", .err) }
    }
    private func deputies() {
        let procs = ProcListLite.snapshot().filter { $0.deputy }
        guard !procs.isEmpty else { emit("no live deputies this census", .err); return }
        for p in procs { emit("★ \(p.pid) \(p.name)", .ok) }
    }
    private func mkdirs(_ p: String?) {
        guard let p else { return }
        do { try FileManager.default.createDirectory(atPath: resolve(p), withIntermediateDirectories: true)
             emit("mkdir ok", .ok) } catch { emit("mkdir: \(String(cString: strerror(errno)))", .err) }
    }
    private func touch(_ p: String?) {
        guard let p else { return }
        let t = resolve(p)
        if FileManager.default.createFile(atPath: t, contents: Data()) { emit("touch ok", .ok) }
        else { emit("touch: \(String(cString: strerror(errno)))", .err) }
    }
    private func rm(_ p: String?) {
        guard let p, p != "/", p != "~" else { return }
        do { try FileManager.default.removeItem(atPath: resolve(p)); emit("rm ok", .ok) }
        catch { emit("rm: \(String(cString: strerror(errno)))", .err) }
    }
}

// MARK: - small proc census + file loader (local, no rig dependency)

struct ProcRowLite: Identifiable { let id = pid; let pid: Int32; let name: String; let deputy: Bool }

enum ProcListLite {
    static let deputies = ["aned", "nesessionmanager", "mlruntimed", "mlhostd", "modelmanagerd",
        "modelcatalogd", "siriinferenced", "corespeechd", "photoanalysisd", "mediaanalysisd",
        "videocodecd", "mobilegestalt", "intelligence", "visualintelligenced"]

    static func snapshot() -> [ProcRowLite] {
        typealias listFn = @convention(c) (UInt32, UInt32, UnsafeMutableRawPointer?, Int32) -> Int32
        typealias pathFn = @convention(c) (Int32, UnsafeMutableRawPointer?, UInt32) -> Int32
        guard let h = dlopen(nil, RTLD_LAZY), let lp = dlsym(h, "proc_listpids"),
              let pp = dlsym(h, "proc_pidpath") else { return [] }
        let listpids = unsafeBitCast(lp, to: listFn.self)
        let pidpath = unsafeBitCast(pp, to: pathFn.self)
        let n = listpids(1, 0, nil, 0)
        guard n > 0 else { return [] }
        var buf = [Int32](repeating: 0, count: Int(n) / 4 + 1)
        let got = listpids(1, 0, &buf, Int32(buf.count * 4))
        guard got > 0 else { return [] }
        var out: [ProcRowLite] = []
        for i in 0..<(Int(got) / 4) {
            let pid = buf[i]
            guard pid > 0 else { continue }
            var pb = [CChar](repeating: 0, count: 4096)
            if pidpath(pid, &pb, 4096) > 0 {
                let path = String(cString: pb)
                let nm = (path as NSString).lastPathComponent
                out.append(ProcRowLite(pid: pid, name: nm,
                    deputy: ProcessLite.deputyOf(nm)))
            }
        }
        return out.sorted { $0.pid < $1.pid }
    }
}

enum ProcessLite {
    static func deputyOf(_ name: String) -> Bool {
        ProcListLite.deputies.contains { name.lowercased().contains($0) }
    }
}

enum FileLoaderLite {
    static func tail(at path: String, maxBytes: Int = 16_384) -> String? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        let size = (try? h.seekToEnd()) ?? 0
        guard size > 0 else { return "" }
        let start = size > UInt64(maxBytes) ? size - UInt64(maxBytes) : 0
        try? h.seek(toOffset: start)
        let d = h.readDataToEndOfFile()
        guard !(d.contains(0)) else { return "[binary \(size) B — use dump]" }
        guard let s = String(data: d, encoding: .utf8) else { return nil }
        return s
    }
}

struct LiteTerminalPane: View {
    @StateObject private var s = LiteSession()
    @State private var entry = ""

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(s.lines) { l in
                            Text(l.text)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(l.kind == .err ? .orange : (l.kind == .ok ? .green : .primary.opacity(0.86)))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled).id(l.id)
                        }
                    }
                    .padding(12)
                }
                .onChange(of: s.lines.count) { v in
                    if let last = s.lines.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
            HStack(spacing: 8) {
                Image(systemName: "chevron.right").font(.system(size: 11, weight: .bold))
                TextField("command…", text: $entry, onCommit: run)
                    .font(.system(size: 12, design: .monospaced))
                    .textInputAutocapitalization(.never).autocorrectionDisabled().submitLabel(.go)
                Button(action: run) { Image(systemName: "return") }
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color(.systemGray6)))
            .padding(.horizontal, 12).padding(.bottom, 10)
        }
        .onAppear { if s.lines.isEmpty { s.submit("help") } }
    }

    private func run() { let c = entry; entry = ""; s.submit(c) }
}

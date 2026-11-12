import SwiftUI

// MARK: - In-app terminal (v1)
//
// Own-container commands run natively; out-of-container READS run through
// LabSandboxRead (the P116 NOFOLLOW harness, lifted verbatim). Nothing here
// writes outside the container. Panic-neutral by construction.

struct TerminalLine: Identifiable {
    let id = UUID()
    let text: String
    let kind: Kind
    enum Kind { case input, out, err, ok }
}

final class TerminalSession: ObservableObject {
    @Published var lines: [TerminalLine] = []
    @Published var cwd = Container.documents.path

    private let start = Date()

    init() {
        banner()
    }

    private func banner() {
        out("LUM1NA terminal — container cwd; out-of-container reads via sbx (P116 NOFOLLOW)")
        out("type 'help' for commands")
    }

    private func stamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: Date())
    }

    func submit(_ raw: String) {
        let cmd = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cmd.isEmpty else { return }
        emit("\(stamp()) \(cwd) $ \(cmd)", .input)
        let parts = cmd.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard let head = parts.first else { return }
        let args = Array(parts.dropFirst())
        switch head {
        case "help": help()
        case "pwd": out(cwd)
        case "cd": changeDir(args.first ?? "")
        case "ls": ls(args.first, long: args.contains("-l"))
        case "cat": cat(args.first)
        case "stat": stat(args.first)
        case "sbx": sbxRead(args.first)
        case "dump": dump(args.first)
        case "ps": ps()
        case "deputies": deputies()
        case "mkdir": mkdir(args.first)
        case "touch": touch(args.first)
        case "rm": rm(args, recursive: false)
        case "echo": out(args.joined(separator: " "))
        case "date": out(stamp())
        case "clear": lines = []
        default: err("unknown '\(head)' — try 'help'")
        }
    }

    private func help() {
        out("""
        pwd · cd <dir> · ls [-l] [path] · cat <f> · stat <p>
        sbx <path>   out-of-container read (64 KB cap, via P116 harness)
        dump <path>  out-of-container full read -> Documents/sbx_<name> (256 MB cap)
        ps · deputies · mkdir <dir> · touch <f> · rm <f> · echo · date · clear
        """)
    }

    private func resolve(_ p: String?) -> String {
        guard var path = p, !path.isEmpty else { return cwd }
        if path.hasPrefix("~/") || path == "~" {
            path = Container.documents.path + path.dropFirst()
        }
        if !path.hasPrefix("/") { path = (cwd as NSString).appendingPathComponent(path) }
        return (path as NSString).standardizingPath
    }

    private func changeDir(_ p: String) {
        let t = resolve(p.isEmpty ? "~" : p)
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: t, isDirectory: &isDir), isDir.boolValue else {
            err("cd: \(t): \(errno == 0 ? "no such directory" : String(cString: strerror(errno)))")
            return
        }
        cwd = t
        out("-> \(t)")
    }

    private func ls(_ p: String?, long: Bool) {
        let t = resolve(p)
        do {
            var names = try FileManager.default.contentsOfDirectory(atPath: t)
            names.sort()
            if names.count > 400 {
                out("(capped at 400 of \(names.count))")
                names = Array(names.prefix(400))
            }
            if long {
                for n in names {
                    let full = (t as NSString).appendingPathComponent(n)
                    let a = try? FileManager.default.attributesOfItem(atPath: full)
                    let size = (a?[.size] as? NSNumber)?.int64Value ?? 0
                    let dir = (a?[.type] as? FileAttributeType) == .typeDirectory
                    out("\(dir ? "d" : "-") \(String(format: "%9d", Int(size)))  \(n)")
                }
            } else {
                out(names.joined(separator: "  "))
            }
        } catch {
            err("ls \(t): \(String(cString: strerror(errno)))")
        }
    }

    private func cat(_ p: String?) {
        guard let p else { err("cat: path required"); return }
        let t = resolve(p)
        if let s = FileLoader.tail(at: t, maxBytes: FileLoader.screenCap * 2) {
            out(s)
        } else if let sbx = LabSandboxRead.read(t, maxBytes: 65_536) {
            out(sbx)
        } else {
            err("cat \(t): unreadable in-container and sbx refused")
        }
    }

    private func stat(_ p: String?) {
        guard let p else { err("stat: path required"); return }
        let t = resolve(p)
        do {
            let a = try FileManager.default.attributesOfItem(atPath: t)
            out("size \(a[.size] ?? "-") · mode \(String((a[.posixPermissions] as? NSNumber)?.intValue ?? 0, radix: 8)) · owner \(a[.ownerAccountName] ?? "-")")
        } catch {
            err("stat \(t): \(String(cString: strerror(errno)))")
        }
    }

    private func sbxRead(_ p: String?) {
        guard let p else { err("sbx: path required"); return }
        if let s = LabSandboxRead.read(resolve(p), maxBytes: 65_536) {
            out(s)
        } else {
            err("sbx refused (issue/consume/open) — honest miss")
        }
    }

    private func dump(_ p: String?) {
        guard let p else { err("dump: path required"); return }
        let r = LabSandboxRead.dump(intoDocuments: resolve(p))
        if let path = r["path"] as? String {
            let bytes = (r["bytes"] as? Int) ?? 0
            ok("dump -> \(path) (\(bytes) B)")
        } else {
            err("dump refused: \(r["error"] as? String ?? "?")")
        }
    }

    private func ps() {
        let procs = ProcList.snapshot()
        out("sysctl/libproc: \(ProcList.status)")
        for p in procs.prefix(60) {
            out("\(String(format: "%7d", Int(p.pid)))  \(p.deputy ? "★ " : "  ")\(p.name)\(p.path.isEmpty ? "" : "  ·  \(p.path)")")
        }
        if procs.count > 60 { out("(… \(procs.count - 60) more)") }
    }

    private func deputies() {
        let procs = ProcList.snapshot().filter(\.deputy)
        if procs.isEmpty { err("no live deputies this census — trigger the class first (CoreML predict wakes ANE users)") }
        for p in procs { ok("★ \(p.pid) \(p.name)\(p.path.isEmpty ? "" : "  ·  \(p.path)")") }
    }

    private func mkdir(_ p: String?) {
        guard let p else { err("mkdir: name required"); return }
        do {
            try FileManager.default.createDirectory(atPath: resolve(p), withIntermediateDirectories: true)
            ok("mkdir \(resolve(p))")
        } catch {
            err("mkdir: \(String(cString: strerror(errno)))")
        }
    }

    private func touch(_ p: String?) {
        guard let p else { err("touch: name required"); return }
        let t = resolve(p)
        if FileManager.default.createFile(atPath: t, contents: Data()) { ok("touch \(t)") }
        else { err("touch: \(String(cString: strerror(errno)))") }
    }

    private func rm(_ args: [String], recursive: Bool) {
        let list = args.filter { $0 != "-r" && $0 != "-rf" }
        guard let p = list.first else { err("rm: path required"); return }
        if p == "/" || p == "~" { err("rm: refusing to touch root/home — lab law"); return }
        do {
            try FileManager.default.removeItem(atPath: resolve(p))
            ok("rm \(resolve(p))")
        } catch {
            err("rm: \(String(cString: strerror(errno)))")
        }
    }

    // MARK: emit helpers
    private func emit(_ s: String, _ k: TerminalLine.Kind) {
        lines.append(TerminalLine(text: s, kind: k))
        if lines.count > 800 { lines.removeFirst(lines.count - 800) }
    }
    func out(_ s: String) { for l in s.components(separatedBy: "\n") where !l.isEmpty { emit(l, .out) } }
    private func err(_ s: String) { emit(s, .err) }
    private func ok(_ s: String) { emit(s, .ok) }
}

struct TerminalPane: View {
    @StateObject private var session = TerminalSession()
    @State private var entry = ""

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(session.lines) { line in
                            Text(line.text)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(color(line.kind))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                                .id(line.id)
                        }
                    }
                    .padding(12)
                }
                .onChange(of: session.lines.count) { _ in
                    if let last = session.lines.last {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
            HStack(spacing: 8) {
                Image(systemName: "chevron.right").font(.system(size: 11, weight: .bold)).foregroundColor(T.ember)
                TextField("command…", text: $entry, onCommit: { run() })
                    .font(.system(size: 12, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .submitLabel(.go)
                Button(action: run) { Image(systemName: "return") }.tint(T.ember)
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(RoundedRectangle(cornerRadius: 10).fill(T.panel))
            .padding(.horizontal, 16).padding(.bottom, 10)
        }
    }

    private func run() {
        let c = entry
        entry = ""
        session.submit(c)
    }

    private func color(_ k: TerminalLine.Kind) -> Color {
        switch k {
        case .input: return .white.opacity(0.55)
        case .err: return T.ember
        case .ok: return T.good
        case .out: return .white.opacity(0.82)
        }
    }
}

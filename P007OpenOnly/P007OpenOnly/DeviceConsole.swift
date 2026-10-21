import Foundation
import Darwin

// DeviceConsole v2.2 — on-device syslog over WiFi (no VPN; we ARE the
// paired host). ObjC DeviceTLS.wrapped Secure Transport provides STARTTLS
// (Swift can't see those constants). Flow: plain lockdown plists →
// EnableSessionSSL → STARTTLS upgrade → StartService(syslog_relay) →
// TLS-from-start service socket → raw syslog stream, logwatch-filtered.

final class DeviceConsole: ObservableObject {
    @Published var lines: [String] = []
    @Published var status: String = "idle"
    private var controlFD: Int32 = -1
    private var serviceFD: Int32 = -1
    private var ctl: UnsafeMutableRawPointer?
    private var svc: UnsafeMutableRawPointer?
    private var running = false
    static let defaultFilter =
        "aks[-_]|AppleSEPKeyStore|AppleKeyStore|IOMD|dmaCommand|IOMobileFramebuffer|IOMFB"
        + "|M2Scaler|IOSurface|Sandbox|CM_KERN|Security: Process"
        + "|unsupported request|invalid handle|unexpected session uid|handle 0 requested|entitled:"
    private var filter: String

    init() {
        let extra = UserDefaults.standard.string(forKey: "rig.logFilter") ?? ""
        filter = extra.isEmpty ? Self.defaultFilter : Self.defaultFilter + "|" + extra
    }
    func start() {
        guard !running else { return }
        running = true
        Thread { self.run() }.start()
    }
    func stop() {
        running = false
        if controlFD >= 0 { close(controlFD); controlFD = -1 }
        if serviceFD >= 0 { close(serviceFD); serviceFD = -1 }
        setStatus("stopped")
    }
    private let logFile: URL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        .appendingPathComponent("device_console_log.txt")

    private func log(_ s: String) {
        DispatchQueue.main.async {
            self.lines.append(s)
            if self.lines.count > 4000 { self.lines.removeFirst(self.lines.count - 4000) }
        }
        // PERSIST (append-only, fsync'd) — the log never disappears on stop/relaunch.
        if let d = (s + "\n").data(using: .utf8) {
            let fd = open(logFile.path, O_CREAT | O_APPEND | O_WRONLY, 0644)
            if fd == -1 { return }
            d.withUnsafeBytes { raw in _ = write(fd, raw.baseAddress, raw.count) }
            fcntl(fd, F_FULLFSYNC)
            close(fd)
        }
    }

    /// the full persisted log = copyable (the sheet's Copy button + files app)
    func logText() -> String {
        (try? String(contentsOf: logFile, encoding: .utf8)) ?? lines.joined(separator: "\n")
    }
    private func setStatus(_ s: String) {
        DispatchQueue.main.async { self.status = s }
        log("[" + s + "]")
    }

    private func run() { autoreleasepool {
        guard let pair = loadPairing() else { setStatus("no valid Documents/Pairing.plist"); return }
        guard let ip = Self.lanIPv4() else { setStatus("no en0/pdp_ip0 IPv4 (Wi-Fi ON?)"); return }
        setStatus("control: \(ip):62078")
        controlFD = Self.tcpConnect("\(ip):62078")
        guard controlFD >= 0 else { setStatus("tcp failed"); return }
        guard Self.sendPlist(controlFD, ["Request": "QueryType", "Label": "Lum1naDevConsole"]) != nil
        else { setStatus("query failed"); return }
        guard let r1 = Self.sendPlist(controlFD, [
            "Request": "StartSession", "Label": "Lum1naDevConsole",
            "HostID": pair.hostID, "SystemBUID": pair.systemBUID,
            "ProtocolVersion": "300"]) else { setStatus("StartSession failed"); return }
        let d1 = Self.dict(r1)
        guard d1["Result"] as? String == "Success" else {
            setStatus("session rejected: \(d1["Error"] ?? "?")"); return
        }
        guard d1["EnableSessionSSL"] as? Bool == true
        else { setStatus("no session SSL"); return }
        var err: NSString?
        ctl = DeviceTLS.upgradeFD(controlFD, cert: pair.hostCert, key: pair.hostKey, errOut: &err)
        guard ctl != nil else { setStatus("STARTTLS failed: \(err ?? "?")"); return }
        setStatus("TLS up — StartService(syslog_relay)")
        let req = Self.binPlist(["Request": "StartService", "Label": "Lum1naDevConsole",
                                 "Service": "com.apple.syslog_relay"])
        let respMaybe = tlsExchange(req)
        guard let resp = respMaybe else { setStatus("StartService no reply"); return }
        let dd = Self.dict(resp)
        guard dd["Result"] as? String == "Success", let port = dd["Port"] as? Int
        else { setStatus("StartService denied: \(dd["Error"] ?? "?")"); return }
        setStatus("relay :\(port)")
        serviceFD = Self.tcpConnect("\(ip):\(port)")
        guard serviceFD >= 0 else { setStatus("service tcp failed"); return }
        svc = DeviceTLS.upgradeFD(serviceFD, cert: pair.hostCert, key: pair.hostKey, errOut: &err)
        guard svc != nil else { setStatus("service TLS failed: \(err ?? "?")"); return }
        setStatus("STREAMING")
        stream()
    }}

    private func stream() {
        var buf = Data()
        let re = try? NSRegularExpression(pattern: filter)
        while running {
            var out = [UInt8](repeating: 0, count: 4096)
            let n = DeviceTLS.tlsRead(svc!, buf: &out, len: 4096)
            guard n != -1 else { setStatus("relay EOF"); return }
            if n == 0 { usleep(20_000); continue }
            buf.append(contentsOf: out[0..<n])
            while let nl = buf.firstIndex(of: 0x0A) {
                var line = buf.subdata(in: buf.startIndex..<nl)
                if line.last == 0x0D { line.removeLast() }
                buf.removeSubrange(buf.startIndex...nl)
                if let s = String(data: line, encoding: .utf8) {
                    let r = NSRange(s.startIndex..., in: s)
                    if re == nil || re!.firstMatch(in: s, range: r) != nil { log(s) }
                }
            }
        }
    }

    private func tlsExchange(_ req: Data) -> Data? {
        var b = [UInt8](req)
        var w = 0
        while w < b.count {
            let n = DeviceTLS.tlsWrite(ctl!, bytes: &b + w, len: b.count - w)
            guard n > 0 else { return nil }
            w += n
        }
        var hdr = [UInt8](repeating: 0, count: 4), got = 0
        while got < 4 {
            let n = DeviceTLS.tlsRead(ctl!, &hdr + got, 4 - got)
            guard n > 0 else { return nil }
            got += n
        }
        let len = (Int(hdr[0]) << 24) | (Int(hdr[1]) << 16) | (Int(hdr[2]) << 8) | Int(hdr[3])
        guard len > 0, len < 4_000_000 else { return nil }
        var body = [UInt8](repeating: 0, count: len)
        got = 0
        while got < len {
            let n = DeviceTLS.tlsRead(ctl!, &body + got, len - got)
            guard n > 0 else { return nil }
            got += n
        }
        return Data(body)
    }

    private func loadPairing() -> (hostID: String, systemBUID: String, hostCert: Data, hostKey: Data)? {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        guard let url = docs?.appendingPathComponent("Pairing.plist"),
              let data = try? Data(contentsOf: url),
              let p = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
        else { return nil }
        let cert = Self.decode(p["HostCertificate"]), key = Self.decode(p["HostPrivateKey"])
        let host = p["HostID"] as? String ?? "", buid = p["SystemBUID"] as? String ?? ""
        return cert.isEmpty || key.isEmpty || host.isEmpty ? nil : (host, buid, cert, key)
    }
    static func decode(_ v: Any?) -> Data {
        if let d = v as? Data { return d }
        if let s = v as? String {
            return s.contains("-----BEGIN") ? Data(s.utf8) : (Data(base64Encoded: s) ?? Data())
        }
        return Data()
    }
    static func binPlist(_ d: [String: Any]) -> Data {
        (try? PropertyListSerialization.data(fromPropertyList: d, format: .binary, options: 0)) ?? Data()
    }
    static func dict(_ d: Data) -> [String: Any] {
        (try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any]) ?? [:]
    }
    static func sendPlist(_ fd: Int32, _ msg: [String: Any]) -> Data? {
        binPlist(msg).withUnsafeBytes { raw -> Data? in
            var hdr = [UInt8((UInt32(raw.count) >> 24) & 0xFF), UInt8((UInt32(raw.count) >> 16) & 0xFF),
                       UInt8((UInt32(raw.count) >> 8) & 0xFF), UInt8(UInt32(raw.count) & 0xFF)]
            var w = 0
            while w < 4 { let n = send(fd, &hdr + w, 4 - w, 0); if n <= 0 { return nil }; w += n }
            var body = [UInt8](raw)
            w = 0
            while w < body.count { let n = send(fd, &body + w, body.count - w, 0); if n <= 0 { return nil }; w += n }
            var rh = [UInt8](repeating: 0, count: 4); w = 0
            while w < 4 { let n = recv(fd, &rh + w, 4 - w, 0); if n <= 0 { return nil }; w += n }
            let len = (Int(rh[0]) << 24) | (Int(rh[1]) << 16) | (Int(rh[2]) << 8) | Int(rh[3])
            guard len > 0, len < 4_000_000 else { return nil }
            var bb = [UInt8](repeating: 0, count: len); w = 0
            while w < len { let n = recv(fd, &bb + w, len - w, 0); if n <= 0 { return nil }; w += n }
            return Data(bb)
        }
    }
    static func tcpConnect(_ addr: String) -> Int32 {
        let parts = addr.split(separator: ":")
        guard parts.count == 2, let port = UInt16(parts[1]) else { return -1 }
        var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(String(parts[0]), String(port), &hints, &res) == 0, let first = res else { return -1 }
        defer { freeaddrinfo(res) }
        let fd = socket(first.pointee.ai_family, first.pointee.ai_socktype, first.pointee.ai_protocol)
        guard fd >= 0 else { return -1 }
        if connect(fd, first.pointee.ai_addr, first.pointee.ai_addrlen) != 0 { close(fd); return -1 }
        return fd
    }
    static func lanIPv4() -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return nil }
        defer { freeifaddrs(ifaddr) }
        var fallback: String?
        var p = ifaddr
        while let c = p {
            let name = String(cString: c.pointee.ifa_name)
            if (name == "en0" || name.hasPrefix("pdp_ip0")),
               c.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_INET),
               var a = c.pointee.ifa_addr {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(&a, socklen_t(c.pointee.ifa_addr!.pointee.sa_len),
                               &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let s = String(cString: host)
                    if name == "en0" { return s }
                    if fallback == nil { fallback = s }
                }
            }
            p = c.pointee.ifa_next
        }
        return fallback
    }
}
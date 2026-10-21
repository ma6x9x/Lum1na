import Foundation
import Security

// DeviceConsole — the true on-device syslog console (v2, the StikDebug
// syslog_relay design adapted; protocol per pymobiledevice3/libimobiledevice).
//
// Path (self-over-WiFi, NO VPN needed — we ARE the device's paired host):
//   1. find the device's own en0/pdp_ip0 IPv4 (lockdownd listens :62078)
//   2. plain-TCP lockdown plist exchange: QueryType → StartSession
//      (HostID + SystemBUID from Documents/Pairing.plist)
//   3. EnableSessionSSL → mid-stream TLS upgrade (Secure Transport on the
//      same fd) with the HOST identity (HostCertificate + HostPrivateKey —
//      the pymobiledevice3 ssl_file pair)
//   4. StartService com.apple.syslog_relay → Port → new TLS socket → the
//      raw device syslog (klog oracle lines INCLUDED)
//
// Filter = the logwatch set default + user patterns (UserDefaults).

final class DeviceConsole: ObservableObject {
    @Published var lines: [String] = []
    @Published var status: String = "idle"
    private var controlFD: Int32 = -1
    private var serviceFD: Int32 = -1
    private var sslCtx: SSLContext?
    private var serverCtx: SSLContext?
    private var running = false
    private var worker: Thread?
    private var filter: String

    static let defaultFilter =
        "aks[-_]|AppleSEPKeyStore|AppleKeyStore|IOMD|dmaCommand|IOMobileFramebuffer|IOMFB"
        + "|M2Scaler|IOSurface|Sandbox|CM_KERN|Security: Process"
        + "|unsupported request|invalid handle|unexpected session uid|handle 0 requested|entitled:"

    init() {
        let extra = UserDefaults.standard.string(forKey: "rig.logFilter") ?? ""
        filter = extra.isEmpty ? Self.defaultFilter
                               : Self.defaultFilter + "|" + extra
    }

    func start() {
        guard !running else { return }
        running = true
        DispatchQueue.main.async { self.status = "starting" }
        worker = Thread { self.run() }
        worker?.name = "device-console"
        worker?.start()
    }

    func stop() {
        running = false
        if controlFD >= 0 { close(controlFD); controlFD = -1 }
        if serviceFD >= 0 { close(serviceFD); serviceFD = -1 }
        DispatchQueue.main.async { self.status = "stopped" }
    }

    private func log(_ s: String) {
        DispatchQueue.main.async {
            self.lines.append(s)
            if self.lines.count > 4000 { self.lines.removeFirst(self.lines.count - 4000) }
        }
    }
    private func setStatus(_ s: String) {
        DispatchQueue.main.async { self.status = s }
        self.log("[" + s + "]")
    }

    // MARK: — run (blocking worker)

    private func run() {
        autoreleasepool {
            guard let pair = loadPairing() else {
                setStatus("no valid Documents/Pairing.plist"); return
            }
            guard let myIP = Self.lanIPv4() else {
                setStatus("no en0/pdp_ip0 IPv4 (Wi-Fi ON?)"); return
            }
            setStatus("lockdownd control: connect \(myIP):62078")
            controlFD = Self.tcpConnect("\(myIP):62078")
            guard controlFD >= 0 else { setStatus("tcp connect failed"); return }

            guard Self.plistSendPair(controlFD, Self.plistMsg([
                "Request": "QueryType", "Label": "Lum1naDeviceConsole"])) == nil
            else { setStatus("querytype failed"); return }

            // StartSession (plaintext)
            let sesReq = Self.plistMsg([
                "Request": "StartSession",
                "Label": "Lum1naDeviceConsole",
                "HostID": pair.hostID,
                "SystemBUID": pair.systemBUID,
                "ProtocolVersion": "300"])
            guard let sesResp = Self.plistSendPair(controlFD, sesReq) else {
                setStatus("startsession failed"); return
            }
            let sesDic = Self.plistDict(sesResp)
            guard sesDic["Request"] as? String == "StartSession",
                  sesDic["Result"] as? String == "Success" else {
                setStatus("session rejected: \(sesDic["Error"] ?? "?")")
                return
            }
            guard sesDic["EnableSessionSSL"] as? Bool == true else {
                setStatus("no session SSL (older train?) — proceed plain unsupported")
                return
            }
            setStatus("STARTTLS upgrade (host identity)")
            guard sslUpgrade(controlFD, pair) else { setStatus("TLS upgrade failed"); return }

            // StartService syslog_relay (over TLS)
            let svcReq = Self.plistMsg([
                "Request": "StartService",
                "Label": "Lum1naDeviceConsole",
                "Service": "com.apple.syslog_relay"])
            guard let svcResp = Self.tlsSendRecvPlist(sslCtx!, svcReq) else {
                setStatus("startservice failed"); return
            }
            let svcDic = Self.plistDict(svcResp)
            guard svcDic["Result"] as? String == "Success",
                  let port = svcDic["Port"] as? Int else {
                setStatus("service denied: \(svcDic["Error"] ?? "?")")
                return
            }
            setStatus("syslog_relay port \(port)")
            serviceFD = Self.tcpConnect("\(myIP):\(port)")
            guard serviceFD >= 0 else { setStatus("service tcp failed"); return }
            guard sslUpgrade(serviceFD, pair) else { setStatus("service TLS failed"); return }

            setStatus("STREAMING (filter active)")
            streamRelay()
        }
    }

    // MARK: — streaming

    private func streamRelay() {
        var buf = Data()
        let regex = (try? NSRegularExpression(pattern: filter)) ?? nil
        while running {
            guard let chunk = tlsReadSome() else { setStatus("relay EOF"); return }
            buf.append(chunk)
            while let nl = buf.firstIndex(of: 0x0A) {
                var line = buf.subdata(in: buf.startIndex..<nl)
                if line.last == 0x0D { line.removeLast() }
                buf.removeSubrange(buf.startIndex...nl)
                guard let s = String(data: line, encoding: .utf8) else { continue }
                if let regex {
                    let r = NSRange(s.startIndex..., in: s)
                    if regex.firstMatch(in: s, range: r) != nil { log(s) }
                } else { log(s) }
            }
        }
    }

    /// blocking-ish read; nil = EOF/err. WouldBlock = retry with a short sleep.
    private func tlsReadSome() -> Data? {
        guard let ctx = sslCtx else { return nil }
        var n = 0
        var buf = [UInt8](repeating: 0, count: 8192)
        let res: OSStatus = withUnsafeMutableBytes(of: &buf) { raw in
            SSLRead(ctx, raw.baseAddress, 8192, &n)
        }
        if n > 0 { return Data(buf[0..<n]) }
        if res == errSSLWouldBlock { usleep(50_000); return Data() } // empty, keep looping
        return nil
    }

    // (tlsReadSome() replaces the old tlsRead; see the streaming section)

    // MARK: — pairing, TLS, sockets (Secure Transport — deprecated but present)

    struct PairRecord {
        var hostID: String = ""
        var systemBUID: String = ""
        var hostCert: Data = Data()
        var hostKey: Data = Data()
    }

    private func loadPairing() -> PairRecord? {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        guard let url = docs?.appendingPathComponent("Pairing.plist"),
              let data = try? Data(contentsOf: url),
              let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
        else { return nil }
        var p = PairRecord()
        p.hostID = plist["HostID"] as? String ?? ""
        p.systemBUID = plist["SystemBUID"] as? String ?? ""
        p.hostCert = decodeCert(plist["HostCertificate"])
        p.hostKey = decodeCert(plist["HostPrivateKey"])
        return p.hostID.isEmpty || p.hostCert.isEmpty || p.hostKey.isEmpty ? nil : p
    }

    private func decodeCert(_ v: Any?) -> Data {
        if let d = v as? Data { return d }
        if let s = v as? String {
            if s.contains("-----BEGIN") { return Data(s.utf8) } // PEM
            return Data(base64Encoded: s) ?? Data()
        }
        return Data()
    }

    private func secIdentity(_ pair: PairRecord) -> SecIdentity? {
        // decode PEM→DER if needed
        var cert = pair.hostCert
        if String(data: cert.prefix(27), encoding: .utf8)?.hasPrefix("-----BEGIN CERTIFICATE") == true {
            cert = Self.pemToDer(cert, tag: "CERTIFICATE")
        }
        guard let certRef = SecCertificateCreateWithData(nil, cert as CFData) else { return nil }
        var keyData = pair.hostKey
        if String(data: keyData.prefix(11), encoding: .utf8)?.hasPrefix("-----BEGIN") == true {
            keyData = Self.pemToDer(keyData, tag: "PRIVATE KEY")
        }
        var err: Unmanaged<CFError>?
        let key = SecKeyCreateWithData(keyData as CFData,
                                       [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                                        kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary,
                                       &err)
        guard let k = key, err == nil else { return nil }
        return SecIdentityCreateWithCertificate(kCFAllocatorDefault, certRef, k)
    }

    private func sslUpgrade(_ fd: Int32, _ pair: PairRecord) -> Bool {
        guard let identity = secIdentity(pair) else { setStatus("identity build failed"); return false }
        let ctx = SSLCreateContext(nil, kSSLClientSide, kSSLStreamType)
        SSLSetConnection(ctx, unsafeBitCast(fd, to: SSLConnectionRef.self))
        SSLSetIOFuncs(ctx, { conn, data, len in
            let fd = unsafeBitCast(conn, to: Int32.self)
            let r = read(fd, data, len)
            return r < 0 && errno != EAGAIN ? errSSLClosedAbort : SSLIOErr(Int(r))
        }, { conn, data, len in
            let fd = unsafeBitCast(conn, to: Int32.self)
            let w = write(fd, data, len)
            return w < 0 ? errSSLClosedAbort : SSLIOErr(Int(w))
        })
        SSLSetCertificate(ctx, [identity as Any] as CFArray)
        SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true)
        // the device presents its own certs; we accept (pairing-model trust)
        var res = errSSLWouldBlock
        while res == errSSLWouldBlock && running {
            res = SSLHandshake(ctx)
            if res == errSSLPeerAuthCompleted { SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, false); continue }
        }
        guard res == errSecSuccess else { setStatus("handshake err=\(res)"); return false }
        if fd == controlFD { sslCtx = ctx } else { serverCtx = ctx }
        return true
    }

    private func secRead(_ ctx: SSLContext, buffer: Int) -> Int {
        var out = [UInt8](repeating: 0, count: buffer)
        var processed = 0
        let res = SSLRead(ctx, &out, buffer, &processed)
        if res == errSSLWouldBlock || res == noErr {
            var chunk = [UInt8](repeating: 0, count: buffer)
            return -1
        }
        return processed
    }

    private func tlsSendRecvPlist(_ ctx: SSLContext, _ msg: Data) -> Data? {
        // write over TLS
        var body = [UInt8](msg)
        var written = 0
        while written < body.count {
            var one = 0
            let r = SSLWrite(ctx, &body + written, body.count - written, &one)
            if r != noErr && r != errSSLWouldBlock { return nil }
            if one <= 0 { return nil }
            written += one
        }
        return readPlistThroughTLS(ctx)
    }

    private func readPlistThroughTLS(_ ctx: SSLContext) -> Data? {
        // 4-byte BE length then bplist — lockdown framing pre-TLS carried
        // per-message; over TLS the same framing applies.
        var hdr = [UInt8](repeating: 0, count: 4)
        var got = 0
        while got < 4 {
            var one = 0
            let r = SSLRead(ctx, &hdr + got, 4 - got, &one)
            if r != noErr && r != errSSLWouldBlock { return nil }
            if one == 0 { return nil }
            got += one
        }
        var len: UInt32 = 0
        for b in hdr { len = (len << 8) | UInt32(b) }
        guard len > 0, len < 4 * 1024 * 1024 else { return nil }
        var body = [UInt8](repeating: 0, count: Int(len))
        got = 0
        while got < Int(len) {
            var one = 0
            let r = SSLRead(ctx, &body + got, Int(len) - got, &one)
            if r != noErr && r != errSSLWouldBlock { return nil }
            if one == 0 { return nil }
            got += one
        }
        return Data(body)
    }

    // MARK: — static helpers

    static func plistMsg(_ dict: [String: Any]) -> Data {
        (try? PropertyListSerialization.data(fromPropertyList: dict,
                                             format: .binary, options: 0)) ?? Data()
    }
    static func plistDict(_ d: Data) -> [String: Any] {
        (try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any]) ?? [:]
    }

    static func plistSendPair(_ fd: Int32, _ body: Data) -> Data? {
        var hdr = [UInt8((UInt32(body.count) >> 24) & 0xFF),
                   UInt8((UInt32(body.count) >> 16) & 0xFF),
                   UInt8((UInt32(body.count) >> 8) & 0xFF),
                   UInt8(UInt32(body.count) & 0xFF)]
        var w = 0
        while w < 4 {
            let n = send(fd, &hdr + w, 4 - w, 0); if n <= 0 { return nil }; w += n
        }
        var b = [UInt8](body)
        w = 0
        while w < b.count {
            let n = send(fd, &b + w, b.count - w, 0); if n <= 0 { return nil }; w += n
        }
        // read 4-byte length + body
        var rh = [UInt8](repeating: 0, count: 4)
        w = 0
        while w < 4 {
            let n = recv(fd, &rh + w, 4 - w, 0); if n <= 0 { return nil }; w += n
        }
        let len = (Int(rh[0]) << 24) | (Int(rh[1]) << 16) | (Int(rh[2]) << 8) | Int(rh[3])
        guard len > 0 && len < 4 * 1024 * 1024 else { return nil }
        var body2 = [UInt8](repeating: 0, count: len)
        w = 0
        while w < len {
            let n = recv(fd, &body2 + w, len - w, 0); if n <= 0 { return nil }; w += n
        }
        return Data(body2)
    }

    static func rawWrite(_ fd: Int32) -> Bool { fd >= 0 }

    static func tcpConnect(_ addr: String) -> Int32 {
        let parts = addr.split(separator: ":")
        guard parts.count == 2, let port = UInt16(parts[1]) else { return -1 }
        var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(String(parts[0]), String(port), &hints, &res) == 0, let first = res else { return -1 }
        defer { freeaddrinfo(res) }
        let fd = socket(first.pointee.ai_family, first.pointee.ai_socktype, first.pointee.ai_protocol)
        guard fd >= 0 else { return -1 }
        var tv = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let r = connect(fd, first.pointee.ai_addr, first.pointee.ai_addrlen)
        guard r == 0 else { close(fd); return -1 }
        tv = timeval(tv_sec: 0, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        return fd
    }

    /// our own en0 / pdp_ip0 IPv4
    static func lanIPv4() -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return nil }
        defer { freeifaddrs(ifaddr) }
        var wan: String?
        var ptr = ifaddr
        while let p = ptr {
            let ifa = p.pointee
            let name = String(cString: ifa.ifa_name)
            if (name == "en0" || name.hasPrefix("pdp_ip0")),
               ifa.ifa_addr?.pointee.sa_family == UInt8(AF_INET),
               var addr = ifa.ifa_addr {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(&addr, socklen_t(ifa.ifa_addr.pointee.sa_len),
                               &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let s = String(cString: host)
                    if name == "en0" { return s }
                    if wan == nil { wan = s }
                }
            }
            ptr = p.pointee.ifa_next
        }
        return wan
    }

    static func pemToDer(_ data: Data, tag: String) -> Data {
        guard let s = String(data: data, encoding: .utf8),
              let begin = s.range(of: "-----BEGIN \(tag)-----"),
              let end = s.range(of: "-----END \(tag)-----"),
              begin.upperBound <= end.lowerBound else { return data }
        let b64 = s[begin.upperBound..<end.lowerBound]
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: " ", with: "")
        return Data(base64Encoded: String(b64)) ?? data
    }
}
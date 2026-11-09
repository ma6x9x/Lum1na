import Foundation
import Security
import CryptoKit
import Darwin

// MARK: - Signing credentials
//
// Imported .p12 / .mobileprovision files live in Documents/Credentials and are
// browsable from the Files tab. They are credentials for signing *another* IPA
// (CI, ESign, Sideloadly, Xcode). They do NOT and cannot change this process's
// code signature: App Groups are read by AMFI from the profile that signed the
// .app at install time. The live row in the pane shows the truth for the
// running process, via SecTaskCopyValueForEntitlement.

struct SigningIdentity: Identifiable, Hashable {
    let fileName: String
    let path: String
    let commonName: String
    let teamID: String
    let notAfter: Date?
    let fingerprint: String
    /// True once the .p12 was opened (empty password included). A locked file
    /// still appears in the list so it can be unlocked in place.
    let unlocked: Bool
    /// True when the passphrase is in the Keychain for a signer to use.
    let passwordStored: Bool

    var id: String { fileName }
    var displayName: String { commonName.isEmpty ? fileName : commonName }
    var expired: Bool { notAfter.map { $0 <= Date() } ?? false }
    var expiryText: String {
        guard let notAfter else { return "—" }
        return Self.date.string(from: notAfter)
    }

    static let date: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()
}

struct SigningProfile: Identifiable, Hashable {
    let fileName: String
    let path: String
    let name: String
    let uuid: String
    let teamID: String
    let appID: String
    let appIDPrefix: String
    let appGroups: [String]
    let entitlements: [String]
    let platforms: [String]
    let expires: Date?
    let devices: [String]
    let getTaskAllow: Bool

    var id: String { fileName }
    var hasLum1naGroup: Bool { appGroups.contains(CredentialParser.luminaGroup) }
    var expired: Bool { expires.map { $0 <= Date() } ?? false }
    var expiryText: String {
        guard let expires else { return "—" }
        return SigningIdentity.date.string(from: expires)
    }
    var deviceCount: Int { devices.count }
    var wildcard: Bool { appID.contains("*") }
    var bundleOfProfile: String {
        appID.split(separator: ".", maxSplits: 1).last.map(String.init) ?? appID
    }
}

// MARK: - Parsers

enum CredentialParser {
    /// The group p160's class-7 path needs and the free team can provision.
    static let luminaGroup = "group.com.Lum1naDebug"

    // MARK: Provisioning profile

    static func profile(at url: URL) -> SigningProfile? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return profile(data: data, fileName: url.lastPathComponent, path: url.path)
    }

    /// A .mobileprovision is a CMS container around an XML plist. The same
    /// `<?xml … </plist>` slice that the p160 profile reader uses is enough;
    /// no CMS decoder and no network.
    static func profile(data: Data, fileName: String, path: String) -> SigningProfile? {
        guard let text = String(data: data, encoding: .isoLatin1),
              let start = text.range(of: "<?xml"),
              let end = text.range(of: "</plist>") else { return nil }
        let xml = String(text[start.lowerBound..<end.upperBound])
        guard let xmlData = xml.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: xmlData, format: nil),
              let obj = plist as? [String: Any] else { return nil }

        let ents = obj["Entitlements"] as? [String: Any] ?? [:]
        let groups: [String]
        if let arr = ents["com.apple.security.application-groups"] as? [String] {
            groups = arr
        } else if let one = ents["com.apple.security.application-groups"] as? String {
            groups = [one]
        } else {
            groups = []
        }
        let appID = ents["application-identifier"] as? String ?? ""
        let prefix = (obj["ApplicationIdentifierPrefix"] as? [String])?.first
            ?? appID.split(separator: ".").first.map(String.init) ?? ""
        let team = (obj["TeamIdentifier"] as? [String])?.first ?? prefix

        return SigningProfile(
            fileName: fileName,
            path: path,
            name: obj["Name"] as? String ?? fileName,
            uuid: obj["UUID"] as? String ?? "—",
            teamID: team,
            appID: appID,
            appIDPrefix: prefix,
            appGroups: groups,
            entitlements: ents.keys.sorted(),
            platforms: obj["Platform"] as? [String] ?? [],
            expires: obj["ExpirationDate"] as? Date,
            devices: obj["ProvisionedDevices"] as? [String] ?? [],
            getTaskAllow: (ents["get-task-allow"] as? Bool) ?? false)
    }

    // MARK: PKCS#12

    /// Returns nil identity plus the OSStatus so the UI can distinguish a
    /// wrong password from a malformed file.
    static func openIdentity(data: Data, password: String) -> (identity: SecIdentity?, status: OSStatus) {
        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: password] as CFDictionary
        let status = SecPKCS12Import(data as CFData, options, &items)
        guard status == errSecSuccess,
              let list = items as? [[String: Any]],
              let first = list.first,
              let raw = first[kSecImportItemIdentity as String] else {
            return (nil, status)
        }
        return ((raw as! SecIdentity), status)
    }

    static func describe(identity: SecIdentity) -> (commonName: String, teamID: String, notAfter: Date?, fingerprint: String)? {
        var certRef: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certRef) == errSecSuccess,
              let cert = certRef else { return nil }
        let cn = (SecCertificateCopySubjectSummary(cert) as String?) ?? ""
        var team = certificateValue(cert, kSecOIDOrganizationalUnitName) ?? ""
        if team.isEmpty,
           let open = cn.range(of: "(", options: .backwards),
           cn.hasSuffix(")") {
            team = String(cn[open.upperBound..<cn.index(before: cn.endIndex)])
        }
        let der = SecCertificateCopyData(cert) as Data
        let fp = SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined()
        return (cn, team, certificateDate(cert, kSecOIDX509V1ValidityNotAfter), fp)
    }

    private static func certificateValue(_ cert: SecCertificate, _ oid: CFString) -> String? {
        guard let values = SecCertificateCopyValues(cert, [oid] as CFArray, nil) as? [String: Any] else {
            return nil
        }
        for raw in values.values {
            guard let entry = raw as? [String: Any] else { continue }
            if let s = entry[kSecPropertyKeyValue as String] as? String, !s.isEmpty { return s }
        }
        return nil
    }

    private static func certificateDate(_ cert: SecCertificate, _ oid: CFString) -> Date? {
        guard let values = SecCertificateCopyValues(cert, [oid] as CFArray, nil) as? [String: Any] else {
            return nil
        }
        for raw in values.values {
            guard let entry = raw as? [String: Any] else { continue }
            if let d = entry[kSecPropertyKeyValue as String] as? Date { return d }
            if let n = entry[kSecPropertyKeyValue as String] as? NSNumber {
                return Date(timeIntervalSinceReferenceDate: n.doubleValue)
            }
        }
        return nil
    }
}

// MARK: - Keychain

/// `.p12` passwords only. Metadata lives in Documents/Credentials/index.json;
/// the secret never touches Documents.
enum CredentialVault {
    private static let service = "com.lum1na.signing"

    static func save(password: String, for account: String) -> Bool {
        let data = Data(password.utf8)
        let base = query(account)
        let attrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updated = SecItemUpdate(base as CFDictionary, attrs as CFDictionary)
        if updated == errSecSuccess { return true }
        var insert = base
        attrs.forEach { insert[$0.key] = $0.value }
        return SecItemAdd(insert as CFDictionary, nil) == errSecSuccess
    }

    static func password(for account: String) -> String? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func remove(for account: String) {
        _ = SecItemDelete(query(account) as CFDictionary)
    }

    static func hasPassword(for account: String) -> Bool { password(for: account) != nil }

    private static func query(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

// MARK: - Live signature

/// The only honest answer to "does this app have the group?". SecTask is
/// dlsym'd for the same reason p160 does it: Security exports the symbols but
/// the public iOS headers do not spell them out.
enum LiveEntitlements {
    private typealias CreateFn = @convention(c) (CFAllocator?) -> Unmanaged<CFTypeRef>?
    private typealias CopyFn = @convention(c) (CFTypeRef, CFString, UnsafeMutableRawPointer?) -> Unmanaged<CFTypeRef>?

    static func value(_ key: String) -> Any? {
        guard let handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY),
              let createSym = dlsym(handle, "SecTaskCreateFromSelf"),
              let copySym = dlsym(handle, "SecTaskCopyValueForEntitlement") else {
            return nil
        }
        defer { dlclose(handle) }
        let create = unsafeBitCast(createSym, to: CreateFn.self)
        let copy = unsafeBitCast(copySym, to: CopyFn.self)
        guard let task = create(nil)?.takeRetainedValue(),
              let raw = copy(task, key as CFString, nil)?.takeRetainedValue() else {
            return nil
        }
        return raw
    }

    static func appGroups() -> [String] {
        guard let v = value("com.apple.security.application-groups") else { return [] }
        if let arr = v as? [String] { return arr }
        if let one = v as? String { return [one] }
        return []
    }

    static func appIdentifier() -> String? {
        value("application-identifier") as? String
    }
}

// MARK: - Pairing record UDID

enum PairingRecord {
    /// The debug job's pairing file is Documents/Pairing.plist. The UDID is not
    /// guaranteed in every record shape, so try the known spellings.
    static func udid() -> String? {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        guard let url = docs?.appendingPathComponent("Pairing.plist"),
              let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dict = plist as? [String: Any] else { return nil }
        for key in ["UDID", "UniqueDeviceID", "DeviceUDID", "TargetDeviceUDID"] {
            if let s = dict[key] as? String, !s.isEmpty { return s }
        }
        return nil
    }
}

// MARK: - Store

final class CredentialStore: ObservableObject {
    static let shared = CredentialStore()

    @Published private(set) var identities: [SigningIdentity] = []
    @Published private(set) var profiles: [SigningProfile] = []
    @Published private(set) var status: String = ""
    @Published private(set) var lastError: String?

    @Published var selectedIdentityID: String? {
        didSet {
            UserDefaults.standard.set(selectedIdentityID, forKey: "cred.identity")
        }
    }
    @Published var selectedProfileID: String? {
        didSet {
            UserDefaults.standard.set(selectedProfileID, forKey: "cred.profile")
        }
    }

    let directory: URL = Container.documents.appendingPathComponent("Credentials", isDirectory: true)
    private let fm = FileManager.default
    private var cache: [String: CachedIdentity] = [:]

    private struct CachedIdentity: Codable {
        var commonName: String
        var teamID: String
        var notAfter: Double?
        var fingerprint: String
        var passwordStored: Bool = false
    }

    private var cacheURL: URL { directory.appendingPathComponent("index.json") }

    init() {
        selectedIdentityID = UserDefaults.standard.string(forKey: "cred.identity")
        selectedProfileID = UserDefaults.standard.string(forKey: "cred.profile")
        reload()
    }

    var selectedIdentity: SigningIdentity? {
        identities.first { $0.fileName == selectedIdentityID }
    }

    var selectedProfile: SigningProfile? {
        profiles.first { $0.fileName == selectedProfileID }
    }

    // MARK: Load

    func reload() {
        ensureDirectory()
        loadCache()
        var ids: [SigningIdentity] = []
        var profs: [SigningProfile] = []
        let names = (try? fm.contentsOfDirectory(atPath: directory.path)) ?? []

        for name in names.sorted() {
            let url = directory.appendingPathComponent(name)
            let lower = name.lowercased()
            if lower.hasSuffix(".p12") || lower.hasSuffix(".pfx") {
                ids.append(loadIdentity(name: name, url: url))
            } else if lower.hasSuffix(".mobileprovision") {
                if let p = CredentialParser.profile(at: url) { profs.append(p) }
            }
        }

        identities = ids
        profiles = profs
        if let id = selectedIdentityID, !ids.contains(where: { $0.fileName == id }) {
            selectedIdentityID = ids.first?.fileName
        }
        if let id = selectedProfileID, !profs.contains(where: { $0.fileName == id }) {
            selectedProfileID = profs.first?.fileName
        }
        saveCache()
    }

    private func loadIdentity(name: String, url: URL) -> SigningIdentity {
        if let cached = cache[name] {
            return SigningIdentity(
                fileName: name, path: url.path,
                commonName: cached.commonName, teamID: cached.teamID,
                notAfter: cached.notAfter.map { Date(timeIntervalSince1970: $0) },
                fingerprint: cached.fingerprint, unlocked: true,
                passwordStored: cached.passwordStored)
        }
        // A fresh file may be unprotected. Try the empty password once, then
        // leave a locked row for the in-pane Unlock control.
        if let data = try? Data(contentsOf: url) {
            let opened = CredentialParser.openIdentity(data: data, password: "")
            if let identity = opened.identity,
               let d = CredentialParser.describe(identity: identity) {
                cache[name] = CachedIdentity(
                    commonName: d.commonName, teamID: d.teamID,
                    notAfter: d.notAfter?.timeIntervalSince1970,
                    fingerprint: d.fingerprint)
                return SigningIdentity(
                    fileName: name, path: url.path,
                    commonName: d.commonName, teamID: d.teamID,
                    notAfter: d.notAfter, fingerprint: d.fingerprint,
                    unlocked: true, passwordStored: false)
            }
        }
        return SigningIdentity(
            fileName: name, path: url.path, commonName: "Encrypted .p12",
            teamID: "", notAfter: nil, fingerprint: "",
            unlocked: false, passwordStored: false)
    }

    // MARK: Import

    @discardableResult
    func importFiles(_ urls: [URL]) -> String {
        ensureDirectory()
        var copied = 0
        var failed: [String] = []

        for src in urls {
            let scoped = src.startAccessingSecurityScopedResource()
            defer { if scoped { src.stopAccessingSecurityScopedResource() } }
            do {
                var name = src.lastPathComponent
                if name.isEmpty { name = "import-\(UUID().uuidString)" }
                let dst = directory.appendingPathComponent(name)
                if fm.fileExists(atPath: dst.path) { try fm.removeItem(at: dst) }
                try fm.copyItem(at: src, to: dst)
                cache.removeValue(forKey: name)
                copied += 1
            } catch {
                failed.append("\(src.lastPathComponent): \(error.localizedDescription)")
            }
        }

        reload()
        if failed.isEmpty {
            status = copied == 0 ? "Nothing imported." : "✓ Imported \(copied) file(s) into Documents/Credentials."
            lastError = nil
        } else {
            status = "✓ \(copied) imported · \(failed.count) failed"
            lastError = failed.joined(separator: "\n")
        }
        return status
    }

    func note(_ text: String) {
        status = text
        lastError = nil
    }

    // MARK: Unlock

    @discardableResult
    func unlock(fileName: String, password: String, remember: Bool) -> String {
        let url = directory.appendingPathComponent(fileName)
        guard let data = try? Data(contentsOf: url) else {
            status = "Missing \(fileName)"
            return status
        }
        let opened = CredentialParser.openIdentity(data: data, password: password)
        guard let identity = opened.identity,
              let d = CredentialParser.describe(identity: identity) else {
            let hint = opened.status == errSecAuthFailed || opened.status == errSecPkcs12VerifyFailure
                ? "wrong password" : "OSStatus \(opened.status)"
            status = "Unlock failed: \(hint)"
            return status
        }
        cache[fileName] = CachedIdentity(
            commonName: d.commonName, teamID: d.teamID,
            notAfter: d.notAfter?.timeIntervalSince1970,
            fingerprint: d.fingerprint)
        var stored = false
        if remember, !password.isEmpty {
            stored = CredentialVault.save(password: password, for: fileName)
        }
        cache[fileName]?.passwordStored = stored
        saveCache()
        reload()
        selectedIdentityID = fileName
        status = "✓ Unlocked \(fileName) — team \(d.teamID.isEmpty ? "?" : d.teamID)"
            + (stored ? " · password in Keychain" : " · password not stored")
        return status
    }

    // MARK: Delete

    func delete(fileName: String) {
        let url = directory.appendingPathComponent(fileName)
        try? fm.removeItem(at: url)
        cache.removeValue(forKey: fileName)
        CredentialVault.remove(for: fileName)
        saveCache()
        reload()
        status = "Removed \(fileName)"
    }

    // MARK: Checks

    struct Check: Identifiable {
        let id: String
        let title: String
        let ok: Bool
        let detail: String
    }

    func checks() -> [Check] {
        var out: [Check] = []
        let identity = selectedIdentity
        let profile = selectedProfile
        let bundle = Bundle.main.bundleIdentifier ?? "?"

        out.append(Check(
            id: "cert", title: "Certificate",
            ok: identity != nil && !(identity?.expired ?? true),
            detail: identity.map { "\($0.teamID.isEmpty ? "team ?" : $0.teamID) · expires \($0.expiryText)" }
                ?? "Select a .p12"))

        out.append(Check(
            id: "profile", title: "Provisioning profile",
            ok: profile != nil && !(profile?.expired ?? true),
            detail: profile.map { "\($0.name) · expires \($0.expiryText)" }
                ?? "Select a .mobileprovision"))

        let teamOK = identity != nil && profile != nil
            && !(identity!.teamID.isEmpty) && identity!.teamID == profile!.teamID
        out.append(Check(
            id: "team", title: "Team matches",
            ok: teamOK,
            detail: teamOK ? "certificate and profile agree"
                : "cert \(identity?.teamID ?? "?") vs profile \(profile?.teamID ?? "?")"))

        let bundleOK: Bool
        if let profile {
            bundleOK = profile.wildcard || profile.bundleOfProfile == bundle
        } else {
            bundleOK = false
        }
        out.append(Check(
            id: "bundle", title: "App ID matches this bundle",
            ok: bundleOK,
            detail: profile.map { "\($0.appID.isEmpty ? "no application-identifier" : $0.appID) · app \(bundle)" }
                ?? "No profile"))

        let groupOK = profile?.hasLum1naGroup ?? false
        out.append(Check(
            id: "group", title: CredentialParser.luminaGroup,
            ok: groupOK,
            detail: groupOK ? "present in profile"
                : (profile?.wildcard ?? false
                    ? "wildcard App IDs cannot carry an app group"
                    : "missing from profile — class 7 will not run")))

        let udid = PairingRecord.udid()
        let deviceOK: Bool
        let deviceDetail: String
        if let profile {
            if let udid, !udid.isEmpty {
                deviceOK = profile.devices.isEmpty || profile.devices.contains(udid)
                deviceDetail = "pairing UDID \(udid) · profile has \(profile.deviceCount) device(s)"
                    + (profile.devices.isEmpty ? " (all devices)" : (profile.devices.contains(udid) ? " · contains this one" : " · DOES NOT contain this one"))
            } else {
                deviceOK = profile.deviceCount > 0
                deviceDetail = "\(profile.deviceCount) device(s) · no Pairing.plist UDID to compare"
            }
        } else {
            deviceOK = false
            deviceDetail = "No profile"
        }
        out.append(Check(id: "device", title: "Device provisioned", ok: deviceOK, detail: deviceDetail))

        out.append(Check(
            id: "gtask", title: "get-task-allow",
            ok: profile?.getTaskAllow ?? false,
            detail: profile.map { $0.getTaskAllow ? "debugger attach permitted" : "not set" } ?? "No profile"))

        let live = LiveEntitlements.appGroups()
        out.append(Check(
            id: "live", title: "Running app has the group",
            ok: live.contains(CredentialParser.luminaGroup),
            detail: live.isEmpty
                ? "no app-group entitlement in this process — a profile in Documents cannot change that"
                : live.joined(separator: ", ")))

        return out
    }

    func handoff() -> String {
        var lines: [String] = []
        lines.append("# Lum1na signing handoff")
        lines.append("bundle: \(Bundle.main.bundleIdentifier ?? "?")")
        lines.append("date: \(ISO8601DateFormatter().string(from: Date()))")
        if let id = selectedIdentity {
            lines.append("identity: \(id.path)")
            lines.append("  team: \(id.teamID.isEmpty ? "?" : id.teamID)")
            lines.append("  expires: \(id.expiryText)")
            lines.append("  sha256: \(id.fingerprint)")
            lines.append("  unlocked: \(id.unlocked ? "yes" : "no")")
            lines.append("  password: \(id.passwordStored ? "in Keychain" : "not stored")")
        } else {
            lines.append("identity: none selected")
        }
        if let p = selectedProfile {
            lines.append("profile: \(p.path)")
            lines.append("  name: \(p.name)")
            lines.append("  uuid: \(p.uuid)")
            lines.append("  team: \(p.teamID)")
            lines.append("  app-id: \(p.appID)")
            lines.append("  app-groups: \(p.appGroups.isEmpty ? "(none)" : p.appGroups.joined(separator: ", "))")
            lines.append("  devices: \(p.deviceCount)")
            lines.append("  expires: \(p.expiryText)")
        } else {
            lines.append("profile: none selected")
        }
        lines.append("")
        lines.append("note: these files sign/install another IPA. They do not grant this running app an app group.")
        return lines.joined(separator: "\n")
    }

    // MARK: Cache

    private func ensureDirectory() {
        if !fm.fileExists(atPath: directory.path) {
            try? fm.createDirectory(at: directory, withIntermediateDirectories: true)
        }
    }

    private func loadCache() {
        guard let data = try? Data(contentsOf: cacheURL),
              let decoded = try? JSONDecoder().decode([String: CachedIdentity].self, from: data) else {
            cache = [:]
            return
        }
        cache = decoded
    }

    private func saveCache() {
        guard let data = try? JSONEncoder().encode(cache) else { return }
        try? data.write(to: cacheURL, options: .atomic)
    }
}

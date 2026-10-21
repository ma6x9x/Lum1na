import SwiftUI
import UniformTypeIdentifiers

// RigSettings — the StikDebug-style setup menu (v1: scaffolding).
//
// Copied design (StikDebug, AGPL-3.0 — github.com/StikDebug/StikDebug):
//   1. LocalDevVPN (a separate user-run app) provides the loopback tunnel.
//   2. The user imports the PAIRING RECORD (.plist / .mobiledevicepairing).
//   3. Over the tunnel: lockdown session → syslog_relay-connect (the TRUE
//      in-app console, incl. kernel klog lines) and mountPersonalDDI for
//      the /System/Developer DDI (debugserver).
// v1 implements: pairing-file import + persistence + validation, the
// console-source preferences, and the LocalDevVPN/DDI status rows.
// v2 (next session): the RSD+lockdown client (syslog_relay / DDI mount).

struct RigSettingsView: View {
    @State private var pairingName: String = ""
    @State private var pairingStatus: String = ""
    @State private var consoleSource: String = UserDefaults.standard.string(forKey: "rig.consoleSource") ?? "klog-only"
    @State private var showImporter = false

    private let pairingDocFile = "Pairing.plist"

    var body: some View {
        NavigationView {
            Form {
                Section("Console (live, filtered)") {
                    Text("LIVE DEVICE CONSOLE = v2.2 (pending): the lockdown session machinery is built and verified up to the STARTTLS gate; the TLS bridge (NWConnection) lands next session. Until then use tools/logwatch.sh on the Mac.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                    Picker("Source", selection: $consoleSource) {
                        Text("In-app (own process os_log)").tag("own-oslog")
                        Text("klog oracle lines only").tag("klog-only")
                        Text("Everything klog-side").tag("klog-all")
                    }
                    .onChange(of: consoleSource) { v in
                        UserDefaults.standard.set(v, forKey: "rig.consoleSource")
                    }
                    Text("klog sources need the paired connection: run LocalDevVPN, import the pairing record, then the syslog_relay client (v2) streams the device syslog in-app. Until v2: run tools/logwatch.sh on the Mac.")
                        .font(.footnote).foregroundColor(.secondary)
                }

                Section("Pairing record") {
                    Button("Import pairing file (.plist / .mobiledevicepairing)") { showImporter = true }
                    if !pairingStatus.isEmpty {
                        Text(pairingStatus).font(.footnote).foregroundColor(.secondary)
                    }
                    HStack {
                        Text("Stored as").font(.footnote).foregroundColor(.secondary)
                        Text("Documents/" + pairingDocFile).font(.footnote)
                    }
                }

                Section("LocalDevVPN") {
                    Text("Status: NOT implemented in-app (v2). Run the LocalDevVPN app first, keep Wi-Fi ON (Airplane-Mode-on-then-off if needed), then re-open the rig. StikDebug uses the same external-VPN model — it is a separate app, not an in-app entitlement.")
                        .font(.footnote).foregroundColor(.secondary)
                }

                Section("Developer Disk Image (DDI)") {
                    Text("mountPersonalDDI(imagePath:trustcachePath:manifestPath:) lands in v2 over the paired session. Post-mount, debugserver is reachable for the lab lane (Developer Mode ON); the 23F77 hunt lane needs none of this.")
                        .font(.footnote).foregroundColor(.secondary)
                }

                Section("License note") {
                    Text("Design adapted from StikDebug (AGPL-3.0). Keep this distribution's sources open under a compatible license.")
                        .font(.footnote).foregroundColor(.secondary)
                }
            }
            .navigationTitle("Rig Settings")
            .fileImporter(isPresented: $showImporter,
                          allowedContentTypes: [.propertyList, .data],
                          allowsMultipleSelection: false) { result in
                importPairing(result)
            }
            .onAppear { refreshPairingStatus() }
        }
    }

    private func refreshPairingStatus() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        let url = docs?.appendingPathComponent(pairingDocFile)
        if let url, let data = try? Data(contentsOf: url) {
            pairingName = url.lastPathComponent
            pairingStatus = validatePairing(data)
        } else {
            pairingStatus = "No pairing record imported yet."
        }
    }

    private func importPairing(_ result: Result<[URL], Error>) {
        switch result {
        case .failure(let e):
            pairingStatus = "Import failed: \(e.localizedDescription)"
        case .success(let urls):
            guard let src = urls.first else { return }
            guard src.startAccessingSecurityScopedResource() else {
                pairingStatus = "Could not access the picked file."
                return
            }
            defer { src.stopAccessingSecurityScopedResource() }
            do {
                let data = try Data(contentsOf: src)
                let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
                let dst = docs.appendingPathComponent(pairingDocFile)
                try data.write(to: dst, options: .atomic)
                pairingName = src.lastPathComponent
                pairingStatus = validatePairing(data)
            } catch {
                pairingStatus = "Copy failed: \(error.localizedDescription)"
            }
        }
    }

    /// Light validation: plist-dict with the pairing-rec keys; prints the
    /// device UDID + hostId presence (no crypto verification in v1 —
    /// the lockdown TLS handshake in v2 does the real verify).
    private func validatePairing(_ data: Data) -> String {
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dict = plist as? [String: Any] else {
            return "Not a plist — StikDebug also accepts .mobiledevicepairing bundles; paste its plist entry."
        }
        let udid = dict["DeviceCertificate"] != nil
        let escrow = dict["EscrowBag"] != nil
        let host = dict["HostID"] as? String ?? "?"
        var s = "Pairing plist OK: keys" + (udid ? " DeviceCertificate" : "") + (escrow ? " EscrowBag" : "")
        s += " — HostID \(host.prefix(12))…"
        s += udid ? " · looks complete." : " · DeviceCertificate missing?"
        return s
    }
}
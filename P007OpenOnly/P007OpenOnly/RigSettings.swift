import SwiftUI
#if canImport(UIKit)
import UIKit
#else
import AppKit
#endif
import UniformTypeIdentifiers

struct DeviceConsoleSheet: View {
    @StateObject private var console = DeviceConsole()
    @State private var interfaces: [(name: String, address: String)] = []

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                DisclosureGroup("Network path (LocalDevVPN / loopback)") {
                    VStack(alignment: .leading, spacing: 3) {
                        if interfaces.isEmpty {
                            Text("No IPv4 interfaces reported.")
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                        ForEach(Array(interfaces.enumerated()), id: \.offset) { _, row in
                            Text("\(row.name)  \(row.address)")
                                .font(.system(size: 10, design: .monospaced))
                        }
                        Text("Tried in order: 127.0.0.1 → 10.7.0.1 → 10.7.1.1 → utun/LAN. A utun entry means LocalDevVPN is up; without one only loopback is live.")
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundColor(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.top, 2)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 4)
                }
                .font(.system(size: 11, design: .monospaced))
                .padding(.horizontal, 10)
                .padding(.vertical, 6)

                Text("status: \(console.status)")
                    .font(.caption.monospaced())
                    .foregroundColor(.secondary)
                    .padding(6)
                List(console.lines.indices.reversed(), id: \.self) { i in
                    Text(console.lines[i])
                        .font(.system(size: 10, design: .monospaced))
                        .lineLimit(2)
                }
                .listStyle(.plain)
            }
            .toolbar {
                ToolbarItem(placement: .automatic) {
                    #if canImport(UIKit)
                    Button { UIPasteboard.general.string = console.logText() } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    #else
                    Button {
                        let pb = NSPasteboard.general
                        pb.clearContents()
                        pb.setString(console.logText(), forType: .string)
                    } label: { Image(systemName: "doc.on.doc") }
                    #endif
                }
            }
            .navigationTitle("Live Device Console")
            .onAppear {
                interfaces = DeviceConsole.interfaceAddresses()
                console.start()
            }
            .onDisappear { console.stop() }
        }
    }
}

struct RigSettingsView: View {
    var onHour: (() -> Void)?
    var onLogs: (() -> Void)?

    @Environment(\.dismiss) private var dismiss
    @State private var showConsole = false
    @State private var showHourSheet = false
    @State private var showLogsSheet = false
    @State private var pairingName: String = ""
    @State private var pairingStatus: String = ""
    @State private var consoleSource: String = UserDefaults.standard.string(forKey: "rig.consoleSource") ?? "klog-only"
    @State private var showImporter = false
    @State private var snap = BoardSnapshot.current()

    private let pairingDocFile = "Pairing.plist"

    var body: some View {
        NavigationStack {
            Form {
                Section("Isolation") {
                    Text("One TAP per force-quit. KERNEL is the hunt door. P099/P073/P130 254-in stay catalog-solo. Unlock UI is a full-width banner while a TAP is running and is never disabled.")
                        .font(.footnote)
                    LabeledContent("Build") { Text(LuminaStamp.ui).font(.footnote.monospaced()) }
                    LabeledContent("Board") {
                        Text(snap.kreadSignal)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                    }
                }

                Section("Beta 1 bar") {
                    LabeledContent("kread") {
                        Text(snap.hasKread ? "YES" : "NO")
                            .font(.footnote.monospaced())
                            .foregroundColor(snap.hasKread ? .green : .red)
                    }
                    LabeledContent("conversion") {
                        Text(snap.conversion ? "YES" : "NO").font(.footnote.monospaced())
                    }
                    LabeledContent("occupancy") {
                        Text(snap.occupancy ? "YES" : "NO").font(.footnote.monospaced())
                    }
                    LabeledContent("leaks") {
                        Text("\(snap.leakCount)").font(.footnote.monospaced())
                    }
                    Text("Beta 1 on this device is kread32(kbase)==0xfeedfacf. Occupancy, PIPE-HIT, and truncated P010 word1 stay NO. AfterKread HOLD until that magic.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                    Button("Copy board + NEXT TAP") {
                        LuminaCopyBus.shared.copy(snap.copyBlock, label: "Board · \(snap.nextID)")
                    }
                }

                Section("SKU door") {
                    Text(snap.sku + "  " + snap.osversion)
                        .font(.footnote.monospaced())
                    Text("NEXT \(snap.nextID) — \(snap.nextWhy)")
                        .font(.footnote)
                    Button("Copy NEXT TAP") {
                        LuminaCopyBus.shared.copy(snap.copyBlock, label: "Next TAP · \(snap.nextID)")
                    }
                    Button("Jump to Tests") {
                        LuminaTabs.shared.index = 0
                        dismiss()
                    }
                    Button("Jump to Chain") {
                        LuminaTabs.shared.index = 2
                        dismiss()
                    }
                    Button("Jump to Console") {
                        LuminaTabs.shared.index = 4
                        dismiss()
                    }
                }

                Section("Logs") {
                    Button("Open log files") {
                        if let onLogs { onLogs() } else { showLogsSheet = true }
                    }
                    Button("Hour gallery") {
                        if let onHour { onHour() } else { showHourSheet = true }
                    }
                    Button("Open Tests") {
                        LuminaTabs.shared.index = 0
                        dismiss()
                    }
                    Text("Copy full lives on each test, on Console Copy, and on the HUD NEXT chip. Files tab previews a 12 KB tail so huge P044/P073 logs cannot jetsam.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }

                Section("Console (live, filtered)") {
                    Button("Open LIVE DEVICE CONSOLE (syslog_relay v2)") { showConsole = true }
                    Picker("Source", selection: $consoleSource) {
                        Text("In-app (own process os_log)").tag("own-oslog")
                        Text("klog oracle lines only").tag("klog-only")
                        Text("Everything klog-side").tag("klog-all")
                    }
                    .onChange(of: consoleSource) { _, v in
                        UserDefaults.standard.set(v, forKey: "rig.consoleSource")
                    }
                    Text("klog sources need the paired connection. Until that lands, use tools/logwatch.sh on the Mac.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
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

                Section("PARK remaining-fire") {
                    Text("Debugger fires every catalog TAP, including EXPECT-BAD. These stay STOP: hop-1, 163-sel AKS sweep, TrollRestore/WVEK, leftover XR close-vs-method (iogpu_close / T014 / p010obj). 86950 glyph is control/oracle, not a Messages/AirDrop payload. AfterKread persist HOLD until kread32.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }

                Section("License note") {
                    Text("Pairing-console layout adapted from StikDebug (AGPL-3.0). Keep this distribution's sources open under a compatible license.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .fileImporter(isPresented: $showImporter,
                          allowedContentTypes: [.propertyList, .data],
                          allowsMultipleSelection: false) { result in
                importPairing(result)
            }
            .sheet(isPresented: $showConsole) { DeviceConsoleSheet() }
            .sheet(isPresented: $showLogsSheet) {
                LogListSheet { body in
                    LuminaCopyBus.shared.copy(body, label: "Log copied")
                    showLogsSheet = false
                    LuminaTabs.shared.index = 4
                    dismiss()
                }
            }
            .sheet(isPresented: $showHourSheet) {
                HourLogGallery { body in
                    LuminaCopyBus.shared.copy(body, label: "Hour log copied")
                    showHourSheet = false
                    LuminaTabs.shared.index = 4
                    dismiss()
                }
            }
            .onAppear {
                refreshPairingStatus()
                snap = BoardSnapshot.current()
            }
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

    private func validatePairing(_ data: Data) -> String {
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dict = plist as? [String: Any] else {
            return "Not a plist — also accepts .mobiledevicepairing bundles; paste its plist entry."
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

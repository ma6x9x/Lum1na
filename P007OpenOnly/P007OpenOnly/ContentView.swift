import SwiftUI
import UIKit
import Darwin

struct ContentView: View {
    @State private var text = "Lum1na \(LuminaStamp.ui). Ident first. One TAP per force-quit. The catalog is the Tests tab. Unlock UI stays tappable during a TAP."
    @State private var copiedFlash = false
    @State private var running = false
    @State private var showHour = false
    @State private var showSettings = false
    @State private var showLogs = false
    @State private var kreadSignal = P007Board.shared().kreadSignal

    var body: some View {
        NavigationStack {
            ZStack {
                LuminaBackdrop()
                VStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(kreadSignal)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                            .textSelection(.enabled)
                        ScrollView {
                            Text(text)
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundStyle(.primary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                                // Cap layout cost — huge recovered logs froze first paint.
                                .lineLimit(running ? 8 : 400)
                        }
                        Text(LuminaStamp.ui)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.tertiary)
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    .background(T.panel, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
                    .padding(.horizontal, 16)
                    .allowsHitTesting(!running)

                    if running {
                        Button {
                            running = false
                            text = "UI unlocked. Probe may still run in background.\n" + text
                        } label: {
                            HStack(spacing: 10) {
                                ProgressView().controlSize(.small)
                                Text("Unlock UI")
                                    .font(.system(size: 16, weight: .semibold))
                                Spacer()
                                Text("frees buttons")
                                    .font(T.tiny)
                                    .foregroundStyle(.secondary)
                            }
                            .foregroundStyle(.primary)
                            .padding(.horizontal, 16)
                            .frame(minHeight: 48)
                        }
                        .luminaGlass(RoundedRectangle(cornerRadius: 22, style: .continuous),
                                     interactive: true, tint: T.accent)
                        .padding(.horizontal, 16)
                    }

                    LazyVGrid(columns: [
                        GridItem(.flexible(), spacing: 10),
                        GridItem(.flexible(), spacing: 10)
                    ], spacing: 10) {
                        huntTile("KERNEL", "cpu", id: "krw", prominent: true)
                        huntTile("PATHS", "arrow.triangle.branch", id: "pathtest", prominent: false)
                        huntTile("Ident", "person.text.rectangle", id: "ident", prominent: false)
                        huntTile("KREAD", "memorychip", id: "kreadtest", prominent: true)
                    }
                    .padding(.horizontal, 16)

                    HStack(spacing: 0) {
                        toolButton(copiedFlash ? "checkmark" : "doc.on.doc", "Copy") {
                            LuminaCopyBus.shared.copy(text, label: "Console copied")
                            copiedFlash = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { copiedFlash = false }
                        }
                        toolButton("doc.text.magnifyingglass", "Recover") { showRecoveredLog() }
                        toolButton("folder", "Logs") { showLogs = true }
                        toolButton("gearshape", "Settings") { showSettings = true }
                    }
                    .luminaGlass(Capsule(), interactive: false)
                    .padding(.horizontal, 16)
                }
                .padding(.bottom, 8)
            }
            .navigationTitle("Console")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar(.hidden, for: .navigationBar)
        }
        // Do NOT scan Documents on first frame — that caused ~1s freeze.
        .sheet(isPresented: $showSettings) {
            RigSettingsView(
                onHour: { showSettings = false; showHour = true },
                onLogs: { showSettings = false; showLogs = true }
            )
        }
        .sheet(isPresented: $showHour) {
            HourLogGallery { body in
                text = body
                showHour = false
            }
        }
        .sheet(isPresented: $showLogs) {
            LogListSheet { body in
                text = body.count > 48_000 ? String(body.suffix(48_000)) : body
                kreadSignal = P007Board.shared().kreadSignal
                showLogs = false
            }
        }
    }

    @ViewBuilder
    private func huntTile(_ title: String, _ systemImage: String, id: String, prominent: Bool) -> some View {
        Button {
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            run(id)
        } label: {
            VStack(alignment: .leading, spacing: 10) {
                Image(systemName: systemImage)
                    .font(.system(size: 18, weight: .semibold))
                Text(title)
                    .font(.system(size: 15, weight: .semibold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
            .foregroundStyle(prominent ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            .frame(maxWidth: .infinity, minHeight: 76, alignment: .leading)
            .padding(14)
            .background {
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .fill(prominent ? T.accent : T.panel)
            }
        }
        .buttonStyle(.plain)
        .disabled(running)
        .opacity(running ? 0.5 : 1)
        .accessibilityLabel(title)
    }

    @ViewBuilder
    private func toolButton(_ system: String, _ label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 3) {
                Image(systemName: system)
                    .font(.system(size: 16, weight: .semibold))
                Text(label)
                    .font(.system(size: 11, weight: .medium))
                    .lineLimit(1)
            }
            .foregroundStyle(.primary)
            .frame(maxWidth: .infinity, minHeight: 48)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(label)
    }

    // After panic+reboot: prefer the log for the *last TAP* (p011_tap_log),
    // not whichever *_log.txt happens to have the newest mtime. A completed
    // p024 SURVIVED session often outlives a panicked p017v2 log that never
    // made it to durable storage — that looks like the "wrong" probe.
    func showRecoveredLog() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let fm = FileManager.default

        let tapToLog: [String: String] = [
            "ident": "device_ident_log.txt",
            "board": "p007_board.json",
            "p022GC": "p022_gc_escape_log.txt",
            "ave47map": "ave64747_map_log.txt",
            "ave47ctl": "ave64747_control_log.txt",
            "ave47vt": "ave64747_vt.txt",
            "ave47vtw": "ave64747_truewrap.txt",
            "p035": "p035_ave_wrap_log.txt",
            "p036": "p036_ave_paint_log.txt",
            "p037": "p037_ave_paint_log.txt",
            "p039": "p039_ave_trigger_log.txt",
            "b1p1": "b1b2_lab_log.txt",
            "b1p2": "b1b2_lab_log.txt",
            "b1p3": "b1b2_lab_log.txt",
            "b1p4": "b1b2_lab_log.txt",
            "p005": "p005_probe_log.txt",
            "p017v2": "p017_confused_deputy_log.txt",
            "p017": "p017_legacy_confused_deputy_log.txt",
            "p024": "p024_necp_string_race_log.txt",
            "p025": "p025_necp_string_spray_log.txt",
            "p026": "p026_metal_nq_cite_log.txt",
            "p027": "p027_metal_callback_log.txt",
            "p028": "p028_reentry_a_log.txt",
            "p029": "p029_hammer_log.txt",
            "p030": "p030_two_queue_log.txt",
            "p031": "p031_reclaim_hit_log.txt",
            "p032": "p032_ane_open_log.txt",
            "p038": "p038_w_hunt_log.txt",
            "p040": "p040_ns_dest_log.txt",
            "p041": "p041_slide_dest_map_log.txt",
            "p009pathb": "p009_pathb_log.txt",
            "p009ranges": "p009_ranges_log.txt",
            "p009types": "p009_types_log.txt",
            "p009detach": "p009_detach_log.txt",
            "p033": "p033_coreml_1in1out_log.txt",
            "p042": "p042_reachability_log.txt",
            "p034": "p034_kmsg3072_occupancy_log.txt",
            "p043": "p043_write_class_map_log.txt",
            "p044": "p044_aks_kaslr_reach_log.txt",
            "conv": "p073_ane_second_table_log.txt",
            "p073": "p073_ane_second_table_log.txt",
            "kreadtest": "p007_kread_test_log.txt",
            "pathtest": "p_path_test_log.txt",
            "krw": "p007_kernel_log.txt",
            "kernel": "p007_kernel_log.txt",
            "p057": "p057_aks_deserialize_log.txt",
            "aks": "p057_aks_deserialize_log.txt",
            "p062": "p062_neon_selftest_log.txt",
            "aio84530": "p84530_aio_kqueue_log.txt",
            "p063": "p84530_aio_kqueue_log.txt",
            "ht149041": "p064_ht149041_chain_log.txt",
            "p064": "p064_ht149041_chain_log.txt",
            "p065": "p065_facet_a_log.txt",
            "facet": "p065_facet_a_log.txt",
            "p066": "p066_ave_enctype_log.txt",
            "p067": "p067_avd_reach_log.txt",
            "p068": "p068_chroot_priv_log.txt",
            "p069": "p069_dma_command_log.txt",
            "p070": "p070_chain_sequencer_log.txt",
            "chains": "p070_chain_sequencer_log.txt",
            "p071": "p071_ane_overflow_log.txt",
            "p072": "p072_file_parser_log.txt",
            "p084": "p084_pmap_tte_puaf_log.txt",
            "p085": "p085_ave84607_racer_log.txt",
            "p086": "p086_iomd_dma_fingerprint_log.txt",
            "p103": "p103_m2scaler_census_log.txt",
            "p108": "p108_diskimages_census_log.txt",
            "p109": "p109_ane_selsweep_log.txt",
            "p113": "p113_descforge_log.txt",
            "p104": "p104_sepks_census_log.txt",
            "p161": "p161_sepks_testuc_log.txt",
            "p105": "p105_iosurface_gates_log.txt",
            "p106": "p106_jpeg_teardown_oracle_log.txt",
            "p107": "p107_ave_wrap_dims_log.txt",
            "p087": "p087_reclaim_observer_log.txt",
            "p045": "p045_kmsg_recv_oracle_log.txt",
            "p046": "p046_f77_patch_oracle_log.txt",
            "p009iopl": "p009_iopl_merge_log.txt",
            "p010obj": "p010_a14_obj_uaf_log.txt",
            "p010leak": "p010_queue_leak_log.txt",
            "p010qleak": "p010_queue_leak_log.txt",
            "p010qspray": "p010_queuespray.txt",
            "p010remain": "p010_remain.txt",
            "p011v3": "p011_wire_log.txt",
            "p011v4": "p011_v4_log.txt",
            "p011v5": "p011_v5_log.txt",
            "p011v6": "p011_v6_log.txt",
            "p011v7": "p011_v7_log.txt",
            "p011v8": "p011_v8_log.txt",
            "p011v9": "p011_v9_log.txt",
            "p011v10": "p011_v10_log.txt",
            "p012ctx": "p012_ctx_log.txt",
            "p013ave": "p013_ave_log.txt",
            "p001a13vt": "p001_a13_vt_ladder_log.txt",
            "p014ane": "p014_ane_log.txt",
            "p014b": "p014b_ane_log.txt",
            "p014close": "p014_close_method_race_log.txt",
            "p015": "p015_log.txt",
            "p016": "p016_log.txt",
            "p018": "p018_log.txt",
            "p019": "p019v2_64749_corrupt_log.txt",
            "p020": "p020_magazine_reclaim_log.txt",
            "p020v2": "p020v2_magazine_drain_log.txt",
            "p021": "p021_agx_stage_mask_log.txt",
            "p022": "p022_cpu0_drain_delay_log.txt",
            "p023": "p023_vt_extreme_log.txt",
            "jpeg_dest": "jpeg_dest_timeout_log.txt",
            "jpeg_fw": "jpeg_fw_decode_log.txt",
            "iogpu_close": "a14_iogpu_close_log.txt",
            "necp": "necp_probe_log.txt",
            "necprace": "necp_race_log.txt",
            "p050": "p050_getattrlist_oob_log.txt",
            "p051": "p051_apfs_xattr_log.txt",
            "p052": "p052_nstream_log.txt",
            "p054": "p054_reap_list_log.txt",
            "p055": "p055_iosurface_upl_log.txt",
            "iopl": "iopl_leak_log.txt",
            "aio": "aio_uaf_log.txt",
            "t018": "t018_cow_log.txt",
            "t018shadow": "t018_cow_log.txt",
            "t018ver": "t018_cow_log.txt",
            "t019": "t019_plreq_log.txt",
            "t014a": "t014_close_log.txt",
            "t014b": "t014_close_log.txt",
            "t014c": "t014_close_log.txt",
            "t014d": "t014_close_log.txt",
            "t014e": "t014_close_log.txt",
            "t014f": "t014_close_log.txt",
            "cscali": "racecalib_log.txt",
            "swordforge": "p122_swordforge_log.txt",
            "shapecensus": "p123_shapecensus_log.txt",
            "cskrw": "clearsword_krw_log.txt",
            "cs2": "cs2_krw_log.txt",
            "intel": "p093_intel_log.txt",
            "luminakrw": "lumina_krw_log.txt",
            "OOB PoC": "p050_getattrlist_oob_log.txt",
            "p053": "p053_necp_dfree_log.txt",
            "P053": "p053_necp_dfree_log.txt",
            "p110": "p110_swapclaim_log.txt",
            "p112": "p112_cgshading_log.txt",
            "p115": "p115_m2peek_log.txt",
            "p116": "p116_sandboxext_toctou_log.txt",
            "p117": "p117_entecho_log.txt",
            "p114": "p114_surfaceleak_log.txt",
            "p118": "p118_bootlearn_log.txt",
            "p119": "p119_staleupl_log.txt",
            "p120": "p120_newresource_log.txt",
            "p121": "p121_closemerge_log.txt",
            "p125": "p125_kernipcrace_log.txt",
            "p126": "p126_decmpfsleak_log.txt",
            "cgshading": "p112_cgshading_log.txt"
        ]

        var preferredName: String? = nil
        var lastTapId: String? = nil
        let tapURL = docs.appendingPathComponent("p011_tap_log.txt")
        if let tapRaw = try? String(contentsOf: tapURL, encoding: .utf8) {
            for line in tapRaw.split(separator: "\n").reversed() {
                let parts = line.split(separator: " ")
                // "TAP p017v2 <date...>"
                if parts.count >= 2, parts[0] == "TAP" {
                    lastTapId = String(parts[1])
                    preferredName = tapToLog[String(parts[1])]
                    break
                }
            }
        }

        func loadLog(named name: String) -> String? {
            let url = docs.appendingPathComponent(name)
            guard let raw = FileLoader.tail(at: url.path, maxBytes: 256_000), !raw.isEmpty else { return nil }
            return Self.lastLogSession(raw)
        }

        // Writers renamed (p051 aks→apfs_xattr, p052 nstream_extend→nstream).
        // Try the mapped name, then leftover filenames from older builds.
        let tapToLogAlias: [String: [String]] = [
            "p051": ["p051_aks_log.txt", "p051_apfs_xattr_log.txt"],
            "p052": ["p052_nstream_extend_log.txt", "p052_nstream_log.txt"],
            "p019": ["p019_64749_log.txt", "p019v2_64749_corrupt_log.txt"],
            "p062": ["p06x_P062_log.txt", "p062_neon_selftest_log.txt"],
        ]
        var recoverNames: [String] = []
        if let name = preferredName { recoverNames.append(name) }
        if let tid = lastTapId, let alts = tapToLogAlias[tid] {
            for a in alts where !recoverNames.contains(a) { recoverNames.append(a) }
        }
        for name in recoverNames {
            if let body = loadLog(named: name) {
                text = "=== RECOVERED (last TAP \(lastTapId ?? "?") → \(name)) ===\n"
                    + P007Board.shared().kreadSignal + "\n"
                    + body
                    + "\n=== end ===\n"
                kreadSignal = P007Board.shared().kreadSignal
                return
            }
        }

        // Fallback: newest mtime among probe logs (old behavior)
        guard let files = try? fm.contentsOfDirectory(
            at: docs,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) else { return }

        let skip: Set<String> = ["p011_tap_log.txt", "p007_board.json"]
        let mappedNames = Set(tapToLog.values)
        var newest: (url: URL, date: Date)?
        for url in files {
            let name = url.lastPathComponent
            let looksLikeLog = name.hasSuffix("_log.txt") || name.hasSuffix("log.txt")
                || mappedNames.contains(name)
            guard looksLikeLog else { continue }
            guard !skip.contains(name) else { continue }
            let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))
                .flatMap(\.contentModificationDate) ?? .distantPast
            if newest == nil || date > newest!.date {
                newest = (url, date)
            }
        }
        guard let win = newest,
              let raw = FileLoader.tail(at: win.url.path, maxBytes: 256_000),
              !raw.isEmpty else {
            if let tid = lastTapId {
                text = "=== RECOVERED ===\n"
                    + "Last TAP was \(tid), but its log file is missing/empty "
                    + "(common after panic before F_FULLFSYNC).\n"
                    + "Check ips PC; re-run that probe after install.\n"
                    + "=== end ===\n"
            }
            return
        }

        let body = Self.lastLogSession(raw)
        var note = ""
        if let tid = lastTapId, preferredName != nil, win.url.lastPathComponent != preferredName {
            note = "(NOTE: last TAP was \(tid) → mapped \(preferredName!); "
                + "file missing, showing newest durable \(win.url.lastPathComponent).)\n"
        }
        text = "=== RECOVERED (newest mtime: \(win.url.lastPathComponent)) ===\n"
            + note
            + body
            + "\n=== end ===\n"
    }

    /// Last *run* only. Do NOT split on `=== verdict` — that ate the full log.
    /// Session headers look like: `=== p025 session … ===` / `=== p024 v7 session … ===`
    static func lastLogSession(_ full: String) -> String {
        let trimmed = full.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return trimmed }
        let lines = trimmed.split(separator: "\n", omittingEmptySubsequences: false)
        var sessionStarts: [Int] = []
        for (i, line) in lines.enumerated() {
            let s = line.trimmingCharacters(in: .whitespaces)
            // Real session banner: starts with === and contains "session"
            if s.hasPrefix("==="), s.lowercased().contains("session") {
                sessionStarts.append(i)
            }
        }
        guard let start = sessionStarts.last else { return trimmed }
        return lines[start...].joined(separator: "\n")
    }

    static func readFreshLog(named name: String, missing: String) -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let path = docs.appendingPathComponent(name)
        guard let raw = FileLoader.tail(at: path.path, maxBytes: 256_000), !raw.isEmpty else {
            return missing
        }
        // Probes truncate per run ("w"); still strip older appended sessions if any.
        return lastLogSession(raw)
    }

    // Append a tap marker to the race log with F_FULLFSYNC (the only
    // panic-surviving flush on Apple platforms) BEFORE dispatching the test.
    // After a panic: marker present but no START line = the ObjC entry never ran.
    func logTap(_ id: String) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let lp = docs.appendingPathComponent("p011_tap_log.txt")
        let fd = open(lp.path, O_CREAT | O_WRONLY | O_APPEND, 0o644)
        if fd >= 0 {
            let s = "TAP \(id) \(LabLocalMilitaryNow() as String)\n"
            s.withCString { write(fd, $0, strlen($0)) }
            fcntl(fd, F_FULLFSYNC)
            close(fd)
        }
    }

    /// Leftover XR / hop-1 / 163-sel / TrollRestore. One list: LuminaTAP.blocked.
    func blockedProbeMessage(_ id: String) -> String? {
        LuminaTAP.blocked(id)
    }

    func run(_ id: String) {
        if let stop = blockedProbeMessage(id) {
            logTap(id)
            text = LuminaLearn.observeParked(id: id, log: stop)
            return
        }

        // p022GC: GameKit can dispatch_sync main while wedged in XPC. Never hold
        // running=true across that — UI stays usable; poll log with magnifying glass.
        if id == "p022GC" {
            logTap(id)
            text = "p022GC v34 — Game Center path oracle. Client write proven earlier.\n"
                + "Want load_raw>=0 or load_over!=client len. NOT KRW.\n"
                + "Log: p022_gc_escape_log.txt  (UI stays unlocked; GameKit can block)\n"
            let th = Thread {
                let body = LuminaTAP.execute("p022GC")
                DispatchQueue.main.async {
                    text = body
                }
            }
            th.name = "p022GC-probe"
            th.start()
            return
        }

        guard !running else { return }
        running = true
        // The Oracle's fleet plan rides every tap's console (the auto-lane:
        // each probe's verdict class feeds the bandit ledger; this line =
        // the ranked cross-domain plan BEFORE the tap runs).
        var planBuf = [CChar](repeating: 0, count: 4096)
        _ = LabBanditPlan(&planBuf, 4096)
        let planText = String(cString: planBuf)
        if !planText.isEmpty {
            text = "[PLAN]\n" + planText
                + "lattice: sandbox → leak → race → write → krw → sptm HOLD\n"
                + "Running \(id)…\nUnlock UI stays tappable. Classify ips after reboot.\n"
        } else {
            text = "Running \(id)…\nUnlock UI stays tappable. Classify ips after reboot.\n"
        }
        logTap(id)

        // 8BADF00D postmortem (P007OpenOnly-2026-10-24-181415/184530 ips):
        // demoting the MAIN thread's QoS while cs2/calib saturate the cores
        // starved the scene-update loop -> FRONTBOARD scene-update watchdog
        // killed the app mid-tap (its 🤯 term flavor). Demotion stays for the
        // P-core A/B/C probes only; cs2/cskrw/cscali no longer throttle the
        // UI thread (their inner race threads set their own QoS).
        let raceHot = (id == "p017v2" || id == "p031" || id == "p050" || id == "p053" || id == "P053")
        if raceHot {
            // Give P-cores to A/B/C (USER_INTERACTIVE in probe). Main/UI → BACKGROUND.
            pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0)
            UIApplication.shared.isIdleTimerDisabled = true
        }

        DispatchQueue.global(qos: raceHot ? .userInitiated : .utility).async {
            let result = LuminaTAP.execute(id)
            DispatchQueue.main.async {
                if raceHot {
                    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0)
                    UIApplication.shared.isIdleTimerDisabled = false
                }
                // Truncate monster returns so SwiftUI doesn't layout megabytes.
                if result.count > 48_000 {
                    text = String(result.prefix(48_000)) + "\n…(truncated; full log in Documents)\n"
                } else {
                    text = result
                }
                Self.snapshotHourLog(result)
                kreadSignal = P007Board.shared().kreadSignal
                running = false
            }
        }
    }

    /// Copy of this tap, so a later O_TRUNC of the probe file does not erase the hour.
    static func snapshotHourLog(_ body: String) {
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "unknown" else { return }
        let fm = FileManager.default
        guard let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
        let dir = docs.appendingPathComponent("hour", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let stamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "")
        let url = dir.appendingPathComponent("\(stamp).txt")
        try? trimmed.write(to: url, atomically: true, encoding: .utf8)
    }
}

private struct HourLogItem: Identifiable, Hashable {
    let id: String
    let name: String
    let modified: Date
    let url: URL
}

struct HourLogGallery: View {
    var onPick: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var items: [HourLogItem] = []

    var body: some View {
        NavigationStack {
            Group {
                if items.isEmpty {
                    Text("No log files touched in the last hour.")
                        .font(.system(.body, design: .rounded))
                        .foregroundStyle(.secondary)
                        .padding()
                } else {
                    List(items) { item in
                        HStack {
                            Button {
                                let body = FileLoader.tail(at: item.url.path, maxBytes: 256_000) ?? "(unreadable)"
                                onPick(body)
                            } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(item.name)
                                        .font(.system(.subheadline, design: .monospaced))
                                        .foregroundStyle(.primary)
                                    Text(item.modified.formatted(date: .omitted, time: .standard))
                                        .font(.system(.caption, design: .rounded))
                                        .foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            Button {
                                UIPasteboard.general.string = FileLoader.tail(at: item.url.path, maxBytes: 256_000) ?? ""
                            } label: {
                                Image(systemName: "doc.on.doc")
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                }
            }
            .navigationTitle("Last hour")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear { items = Self.load() }
        }
    }

    /// Scanned only when the sheet opens.
    private static func load() -> [HourLogItem] {
        let fm = FileManager.default
        guard let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first else { return [] }
        let cutoff = Date().addingTimeInterval(-3600)
        let hourDir = docs.appendingPathComponent("hour", isDirectory: true)
        var items: [HourLogItem] = []

        func consider(_ url: URL) {
            let name = url.lastPathComponent
            let isLog = name.hasSuffix("_log.txt") || name.hasSuffix(".txt")
            guard isLog else { return }
            let modified = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate ?? .distantPast
            if modified < cutoff {
                if url.path.hasPrefix(hourDir.path) { try? fm.removeItem(at: url) }
                return
            }
            let label = url.deletingLastPathComponent().lastPathComponent == "hour"
                ? "hour/\(name)" : name
            items.append(HourLogItem(id: label, name: label, modified: modified, url: url))
        }

        if let urls = try? fm.contentsOfDirectory(
            at: docs,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) {
            for url in urls where url.lastPathComponent.hasSuffix("_log.txt") {
                consider(url)
            }
        }
        if let snaps = try? fm.contentsOfDirectory(
            at: hourDir,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) {
            for url in snaps { consider(url) }
        }
        return items.sorted { $0.modified > $1.modified }
    }
}

/// Documents TAP logs. Tail-only so a huge P044/P073 file cannot jetsam the UI.
struct LogListSheet: View {
    var onPick: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var items: [(name: String, path: String, size: Int64, date: Date)] = []
    @State private var copied: String?

    var body: some View {
        NavigationStack {
            List {
                if items.isEmpty {
                    Text("No *_log.txt in Documents yet. Run KERNEL or a probe first.")
                        .font(.system(.body, design: .rounded))
                        .foregroundStyle(.secondary)
                }
                ForEach(items, id: \.path) { item in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(item.name)
                            .font(.system(.subheadline, design: .monospaced))
                        Text(byteCount(item.size) + " · " + item.date.formatted(date: .omitted, time: .standard))
                            .font(.system(.caption, design: .rounded))
                            .foregroundStyle(.secondary)
                        HStack {
                            Button("Open tail") {
                                let body = FileLoader.tail(at: item.path, maxBytes: 256_000) ?? "(unreadable)"
                                onPick("=== LOG \(item.name) ===\n" + body)
                            }
                            .buttonStyle(.bordered)
                            Button(copied == item.path ? "Copied" : "Copy tail") {
                                UIPasteboard.general.string = FileLoader.tail(at: item.path, maxBytes: 256_000) ?? ""
                                copied = item.path
                            }
                            .buttonStyle(.borderedProminent)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            .navigationTitle("TAP logs")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear { items = Self.load() }
        }
    }

    private func byteCount(_ n: Int64) -> String {
        let f = ByteCountFormatter()
        f.countStyle = .file
        return f.string(fromByteCount: n)
    }

    private static func load() -> [(name: String, path: String, size: Int64, date: Date)] {
        let fm = FileManager.default
        guard let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first else { return [] }
        var out: [(name: String, path: String, size: Int64, date: Date)] = []

        func consider(_ url: URL, label: String) {
            let name = url.lastPathComponent
            let keep = name.hasSuffix("_log.txt") || name == "p007_board.json" || name == "p011_tap_log.txt"
                || name == "cinder_lab_log.txt" || name.hasSuffix(".json") && name.contains("journal")
            guard keep else { return }
            let rv = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
            out.append((label, url.path, Int64(rv?.fileSize ?? 0), rv?.contentModificationDate ?? .distantPast))
        }

        if let urls = try? fm.contentsOfDirectory(
            at: docs,
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
            options: [.skipsHiddenFiles]
        ) {
            for url in urls { consider(url, label: url.lastPathComponent) }
        }
        let cinder = docs.appendingPathComponent("cinder", isDirectory: true)
        if let urls = try? fm.contentsOfDirectory(
            at: cinder,
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
            options: [.skipsHiddenFiles]
        ) {
            for url in urls { consider(url, label: "cinder/\(url.lastPathComponent)") }
        }
        return out.sorted { $0.date > $1.date }
    }
}

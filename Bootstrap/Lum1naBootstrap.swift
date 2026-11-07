//
//  Lum1naBootstrap.swift
//  Lum1na
//
//  The real post-KRW pipeline coordinator. Ordering mirrors Dopamine
//  3.0.10 / Relaxin-RootHide: stage BaseBin + the Sileo/Zebra debs, then
//  the KRW self-test gate, then pmap_cs -> AMFI trust cache ->
//  opainject launchdhook -> dpkg -i Sileo then Zebra -> jbctl respring.
//
//  Honesty contract (AGENTS.md): everything below the gate fires ONLY on
//  a passing self-test (kread32(kbase)==MH_MAGIC_64 and kbase+0x1c is a
//  kernel VA). There is no simulated path. HOLD means HOLD.
//  Post-respring state is detected from the filesystem: a jbroot dpkg
//  binary and Sileo/Zebra app bundles either exist or they do not.
//

import Foundation
import Observation

@MainActor
final class Lum1naBootstrap: ObservableObject, BootstrapCoordinator {

    static let shared = Lum1naBootstrap()

    /// Dopamine-style custom respring logo. The C respring path writes a
    /// timestamp flag and posts `Lum1naWillRespring` immediately before the
    /// jbctl spawn, then holds for 1.5 s; this boolean paints the full-screen
    /// LUM1NA splash in that window (and once after relaunch, briefly).
    @Published private(set) var respringSplashVisible = false
    private var respringObserver: NSObjectProtocol?

    init() {
        respringObserver = NotificationCenter.default.addObserver(
            forName: .lum1naWillRespring, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.respringSplashVisible = true
            }
        }
        consumeRespringSplashFlag()
    }

    func dismissRespringSplash() {
        respringSplashVisible = false
    }

    /// Post-respring logo: the flag is written by ak_tryRespring() just before
    /// the real respring. Show it once if the relaunch is recent, then delete.
    private func consumeRespringSplashFlag() {
        let fm = FileManager.default
        guard let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return
        }
        let url = docs.appendingPathComponent("lum1na_respring_splash")
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return }
        try? fm.removeItem(at: url)
        let stamp = TimeInterval(text.split(separator: "\n").first.flatMap { Double(String($0)) } ?? 0)
        let age = Date().timeIntervalSince1970 - stamp
        guard stamp > 0, age >= 0, age < 600 else { return }
        respringSplashVisible = true
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 2_400_000_000)
            self?.respringSplashVisible = false
        }
    }

    enum Phase: String {
        case idle      = "IDLE"
        case staging   = "STAGING"
        case gate      = "KRW GATE"
        case injected  = "INJECTED"
        case pkgman    = "PKGMAN"
        case respring  = "RESPRING"
        case hold      = "HOLD"
        case installed = "INSTALLED"
    }

    /// Rootless jbroot locations (Dopamine /var/jb, roothide .jbroot).
    static let jbRoots: [String] = [
        "/var/jb",
        "/var/containers/Bundle/Application/.jbroot",
        "/var/jb.orig",
    ]

    @Published private(set) var phase: Phase = .idle
    /// Real evidence: a jbroot /usr/bin/dpkg executable is present.
    @Published private(set) var bootstrapInstalled = false
    /// "Sileo", "Sileo + Zebra" — app bundles found in the jbroot.
    @Published private(set) var pkgmanInstalled: String?
    @Published private(set) var lastHoldReason: String?

    // MARK: - BootstrapCoordinator

    func validatePrerequisites() throws {
        var missing: [String] = []
        for name in ["basebin.tar", "basebin.tc", "sileo.deb", "zebra.deb"]
        where Self.find(name) == nil {
            missing.append(name)
        }
        guard missing.isEmpty else {
            throw NSError(
                domain: "Lum1naBootstrap", code: 1,
                userInfo: [NSLocalizedDescriptionKey:
                    "payload missing: \(missing.joined(separator: ", "))"])
        }
    }

    /// STAGE: extract basebin.tar into Documents/basebin, copy the debs
    /// into Documents/pkgman (delegated to Lum1naAfterKread stageOnly).
    /// Runs off the main actor — tar extraction is real file I/O.
    func prepare() async throws {
        try validatePrerequisites()
        phase = .staging
        let _: String = await Task.detached(priority: .userInitiated) {
            Lum1naAfterKread.stageOnly() as String
        }.value
    }

    /// FIRE: the gated pipeline. HOLD text comes back unless the KRW
    /// self-test passes; nothing below the gate runs without it.
    /// Runs off the main actor — AMFI IOServiceOpen + spawn live here.
    func runGatedPipeline() async {
        phase = .gate
        lastHoldReason = nil
        let log: String = await Task.detached(priority: .userInitiated) {
            Lum1naAfterKread.fire() as String
        }.value
        classify(log)
    }

    // MARK: - Post-respring truth

    /// Called at launch and after every full chain. Files exist or they
    /// do not — this is detection, not a claim of success.
    func refreshInstalledState() {
        let fm = FileManager.default
        var jbroot: String?
        for candidate in Self.jbRoots {
            let p = candidate + "/usr/bin/dpkg"
            if fm.isExecutableFile(atPath: p) { jbroot = candidate; break }
        }
        bootstrapInstalled = (jbroot != nil)

        var found: [String] = []
        if let jbroot {
            let apps = jbroot + "/applications"
            let entries = (try? fm.contentsOfDirectory(atPath: apps)) ?? []
            let lower = entries.map { $0.lowercased() }
            if lower.contains(where: { $0.hasPrefix("sileo") }) { found.append("Sileo") }
            if lower.contains(where: { $0.hasPrefix("zebra") }) { found.append("Zebra") }
        }
        pkgmanInstalled = found.isEmpty ? nil : found.joined(separator: " + ")

        if bootstrapInstalled {
            phase = .installed
        } else if phase == .installed {
            phase = .idle
        }
    }

    // MARK: - Phase classification from the FIRE log

    private func classify(_ log: String) {
        if log.contains("FIRING:") {
            if log.contains("respring via") {
                phase = .respring
            } else if log.contains("dpkg -i") {
                phase = .pkgman
            } else {
                phase = .injected
            }
        } else if let line = log.split(separator: "\n").first(where: { $0.contains("HOLD:") }) {
            phase = .hold
            lastHoldReason = line.trimmingCharacters(in: .whitespaces)
        }
        refreshInstalledState()
    }

    // MARK: - Payload lookup (mirrors ak_findFile roots)

    nonisolated static func find(_ name: String) -> String? {
        let fm = FileManager.default
        var roots: [URL] = []
        if let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first {
            roots += [docs,
                      docs.appendingPathComponent("basebin"),
                      docs.appendingPathComponent("pkgman")]
        }
        if let res = Bundle.main.resourceURL {
            roots += [res,
                      res.appendingPathComponent("basebin"),
                      res.appendingPathComponent("pkgman")]
        }
        for root in roots {
            let p = root.appendingPathComponent(name).path
            if fm.fileExists(atPath: p) { return p }
        }
        let base = name as NSString
        return Bundle.main.path(
            forResource: base.deletingPathExtension,
            ofType: base.pathExtension.isEmpty ? nil : base.pathExtension)
    }
}
extension Notification.Name {
    /// Posted by ak_tryRespring() in Lum1naAfterKread.m immediately before the
    /// jbctl respring spawn. The app paints the LUM1NA respring splash inside
    /// the deliberate 1.5 s hold (Dopamine-style custom respring logo).
    static let lum1naWillRespring = Notification.Name("Lum1naWillRespring")
}

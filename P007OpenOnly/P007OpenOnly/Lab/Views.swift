import SwiftUI
import UIKit

struct RootView: View {
    @EnvironmentObject private var engine: LabEngine
    @Environment(\.gateInfo) private var gate
    @ObservedObject private var tabs = LuminaTabs.shared

    var body: some View {
        TabView(selection: $tabs.index) {
            TestsView()
                .tabItem { Label("Tests", systemImage: "list.bullet") }
                .tag(0)

            ModView()
                .tabItem { Label("Tools", systemImage: "wrench.and.screwdriver") }
                .tag(1)

            ChainView()
                .tabItem { Label(t("tab.chain"), systemImage: "link") }
                .tag(2)

            ContentView()
                .tabItem { Label(t("tab.console"), systemImage: "text.alignleft") }
                .tag(3)
        }
        .tint(T.accent)
        .onAppear {
            if let env = ProcessInfo.processInfo.environment["LUM1NA_TAB"],
               let n = Int(env) {
                // Older IPAs used 3 for More and 4 for Console.
                switch n {
                case 4: tabs.index = 3
                case 3: tabs.index = 1
                default: tabs.index = n
                }
            }
        }
        .overlay(alignment: .bottom) {
            CopyToastOverlay()
                .padding(.bottom, 88)
        }
        .onAppear {
            Container.ensureAll()
            runAutorunIfRequested()
        }
    }

    /// Nothing in this app runs on its own. Every primitive stays at "not run" until the
    /// user presses Execute.
    ///
    /// The only exception is an opt-in harness for automated testing, and it needs *two*
    /// independent conditions: the environment variable `LUM1NA_AUTORUN` naming a module,
    /// and a file called `enable-autorun` sitting in the container. A shipped build has
    /// neither, so a normal launch cannot execute anything.
    private func runAutorunIfRequested() {
        let env = ProcessInfo.processInfo.environment
        guard let id = env["LUM1NA_AUTORUN"], !id.isEmpty else { return }

        let marker = Container.appSupport.appendingPathComponent("enable-autorun")
        guard FileManager.default.fileExists(atPath: marker.path) else { return }
        guard let module = Catalog.byID[id] else { return }

        print("[AUTORUN] \(id)")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            engine.run(module)
            if env["LUM1NA_AUTORUN_EXIT"] == "1" {
                DispatchQueue.main.asyncAfter(deadline: .now() + 6.0) {
                    print("[AUTORUN] exit")
                    exit(0)
                }
            }
        }
    }
}

// MARK: - Dashboard

struct DashboardView: View {
    @EnvironmentObject private var engine: LabEngine
    @Environment(\.gateInfo) private var gate
    @State private var device = DeviceModel.current()
    @State private var showSettings = false

    private var tested: Int { Catalog.all.filter { engine.journal.verdict(for: $0.id) != .untested }.count }
    private var died: Int { Catalog.all.filter { engine.journal.verdict(for: $0.id) == .processDied }.count }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    header
                    SKUDoorCard()
                    deviceCard
                    capabilityCard

                    HStack(spacing: 12) {
                        statTile(t("ov.modules"), "\(Catalog.all.count)", T.info)
                        statTile(t("ov.tested"), "\(tested)", T.warn)
                        statTile(t("ov.died"), "\(died)", T.ember)
                    }

                    if tested > 0 {
                        HStack(spacing: 10) {
                            RunButton(title: t("ov.reset"), systemImage: "arrow.counterclockwise",
                                      tint: T.info) {
                                engine.journal.clear()
                            }
                            RunButton(title: "Copy all logs", systemImage: "doc.on.doc",
                                      tint: T.ember) {
                                LuminaCopyBus.shared.copy(engine.copyAllResults(), label: "All logs copied")
                            }
                        }
                    }

                    if !engine.journal.recovered.isEmpty { interruptedCard }
                    logCard
                }
                .padding(16)
            }
            .luminaCanvas()
            .navigationTitle("Lum1na")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .tint(T.cyan)
                }
            }
            .sheet(isPresented: $showSettings) {
                RigSettingsView()
            }
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            LuminaMark(size: 54)
            VStack(alignment: .leading, spacing: 6) {
                Text("Lum1na")
                    .font(T.title)
                    .foregroundStyle(.primary)
                Text(t("ov.headline"))
                    .font(T.body)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(String(format: t("ov.sub"), Catalog.all.count, Catalog.locatedFixes))
                    .font(T.tiny)
                    .foregroundColor(.white.opacity(0.4))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var deviceCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    SectionLabel(text: t("ov.target"))
                    Spacer()
                    Pill(text: device.vulnerabilityClass == "VULNERABLE" ? t("verdict.vulnerable")
                         : device.vulnerabilityClass == "PATCHED" ? t("verdict.patched") : t("verdict.unknown"),
                         color: device.vulnerabilityClass == "VULNERABLE" ? T.ember : T.good)
                }
                KeyValueRow(key: t("ov.model"), value: "\(device.marketingName) (\(device.machine))")
                KeyValueRow(key: t("ov.os"), value: "iOS \(device.osVersion)  (\(device.osBuild))")
                KeyValueRow(key: t("ov.kernel"), value: device.kernel)
                KeyValueRow(key: t("ov.memory"),
                            value: ByteCountFormatter.string(fromByteCount: Int64(device.physicalMemory),
                                                            countStyle: .memory))
            }
        }
    }

    private var capabilityCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionLabel(text: t("ov.capabilities"))
                ForEach(Capability.matrix()) { row in
                    HStack(spacing: 10) {
                        Text(row.level)
                            .font(T.monoSm)
                            .foregroundColor(row.achieved ? T.good : .white.opacity(0.25))
                            .frame(width: 24, alignment: .leading)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(row.name).font(T.body)
                                .foregroundColor(row.achieved ? .white.opacity(0.9) : .white.opacity(0.4))
                            Text(row.detail).font(T.monoSm)
                                .foregroundColor(.white.opacity(0.28))
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        Spacer()
                        Image(systemName: row.achieved ? "checkmark.circle.fill" : "lock.fill")
                            .font(.system(size: 12))
                            .foregroundColor(row.achieved ? T.good : .white.opacity(0.18))
                    }
                }
            }
        }
    }

    private var interruptedCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                SectionLabel(text: t("ov.interrupted"))
                ForEach(engine.journal.recovered) { e in
                    HStack {
                        Circle().fill(T.ember).frame(width: 6, height: 6)
                        Text(e.moduleID).font(T.mono)
                        Spacer()
                        Text(e.detail).font(T.monoSm).foregroundColor(.white.opacity(0.4))
                    }
                }
                Text(t("ov.interrupted.note"))
                    .font(T.tiny).foregroundColor(.white.opacity(0.35))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var logCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SectionLabel(text: t("ov.log"))
                    Spacer()
                    Button("Copy") {
                        LuminaCopyBus.shared.copy(engine.copyAllResults(), label: "Logs copied")
                    }
                    .font(.system(size: 11, weight: .semibold))
                    .tint(T.ember)
                }
                if engine.logLines.isEmpty {
                    Text(t("ov.log.empty")).font(T.monoSm).foregroundColor(.white.opacity(0.3))
                } else {
                    ForEach(Array(engine.logLines.suffix(8).enumerated()), id: \.offset) { _, line in
                        Text(line).font(T.monoSm).foregroundColor(.white.opacity(0.55))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Text("Full Lab log: Documents/lum1na_lab_log.txt  ·  per-module Documents/lum1na/<id>_log.txt")
                    .font(T.tiny)
                    .foregroundColor(.white.opacity(0.32))
            }
        }
    }

    private func statTile(_ title: String, _ value: String, _ color: Color) -> some View {
        VStack(spacing: 4) {
            Text(value).font(.system(size: 22, weight: .bold, design: .rounded)).foregroundColor(color)
            Text(title).font(T.tiny).foregroundColor(.white.opacity(0.4))
        }
        .frame(maxWidth: .infinity, minHeight: 72)
        .padding(.vertical, 14)
        .background(T.panel, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .strokeBorder(Color.primary.opacity(0.08), lineWidth: 0.5)
        )
    }
}

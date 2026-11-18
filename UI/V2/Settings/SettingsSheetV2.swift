//
//  SettingsSheetV2.swift
//  Lum1na — pushed Settings page from Tests (tab bar stays visible).
//

import SwiftUI

struct SettingsSheetV2: View {
    @Environment(LuminaAppStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    private let bufferChoices = [2_000, 5_000, 10_000, 20_000, 50_000]

    var body: some View {
        @Bindable var store = store
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                settingsCard("GENERAL") {
                    toggleRow("Confirm before run", isOn: $store.settings.confirmBeforeRun)
                    toggleRow("Pin last summary", isOn: $store.settings.pinLastSummary)
                }

                settingsCard("TESTS & PROBES") {
                    pickerRow("Default group", selection: $store.settings.defaultGroup) {
                        ForEach([TestGroup.probes, .taps, .chains, .kernelReads], id: \.self) { g in
                            Text(g.rawValue).tag(g)
                        }
                    }
                    toggleRow("Compact badges", isOn: $store.settings.compactBadges)
                }

                settingsCard("CHAINS") {
                    toggleRow("Stop on failure", isOn: $store.settings.stopOnFailure)
                    // Auto-advance steps hidden until wired into sequencer advance
                    // (executeStage is atomic; UI-only toggle would be a façade).
                }

                settingsCard("CONSOLE & LOGGING") {
                    toggleRow("Live stream", isOn: $store.settings.liveStream)
                    pickerRow("Buffer size", selection: Binding(
                        get: { store.settings.bufferSize },
                        set: { store.settings.bufferSize = $0; store.syncLinesFromManager() }
                    )) {
                        ForEach(bufferChoices, id: \.self) { n in
                            Text("\(n.formatted()) lines").tag(n)
                        }
                    }
                    pickerRow("Timestamps", selection: $store.settings.timestampMode) {
                        ForEach(TimestampMode.allCases) { m in
                            Text(m.rawValue).tag(m)
                        }
                    }
                    .onChange(of: store.settings.timestampMode) { _, mode in
                        store.settings.showMilliseconds = (mode == .milliseconds)
                    }
                    pickerRow("Default level", selection: $store.settings.defaultLogLevel) {
                        ForEach(ConsoleDefaultLevel.allCases) { m in
                            Text(m.rawValue).tag(m)
                        }
                    }
                    .onChange(of: store.settings.defaultLogLevel) { _, level in
                        // Severity floor always applies in Console; Error also selects Error+ chip.
                        if level == .error {
                            store.consoleLevelFilter = .error
                        }
                    }
                }

                settingsCard("APPEARANCE") {
                    pickerRow("CRT tint", selection: $store.settings.crtTint) {
                        ForEach(CRTTint.allCases) { t in
                            Text(t.rawValue).tag(t)
                        }
                    }
                    toggleRow("Scanlines", isOn: $store.settings.crtScanlines)
                }

                settingsCard("DEVICE & SKU") {
                    labeled("Machine", store.machine)
                    labeled("Board", store.boardConfig)
                    labeled("iOS", store.iosVersion)
                    labeled("Build", store.build)
                    labeled("Offset table", store.skuTag)
                    labeled("hasKread", store.hasKread ? "yes" : "no")
                    labeled("conversion", store.conversionConfirmed ? "yes" : "no")
                    labeled("magic", store.magicConfirmed ? "yes" : "no")
                }

                settingsCard("DATA & EXPORT") {
                    buttonRow("Copy console buffer", systemImage: "terminal") {
                        store.copyToPasteboard(store.exportConsole())
                    }
                    buttonRow("Share console buffer", systemImage: "square.and.arrow.up") {
                        store.share(store.exportConsole())
                    }
                    buttonRow("Copy board JSON", systemImage: "cpu") {
                        store.copyToPasteboard(Lum1naBoard.shared().jsonDump())
                    }
                    buttonRow("Reset session state", systemImage: "arrow.counterclockwise", danger: true) {
                        store.resetSession()
                    }
                }

                settingsCard("AI") {
                    Text("Download AI model — lands in a follow-up pass (Qwen3.5-2B GGUF). Not wired in this shell.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 4)
                }
            }
            .padding(16)
            .padding(.bottom, LuminaV2Theme.chipClearance + LuminaV2Theme.tabBarHeight)
        }
        .scrollContentBackground(.hidden)
        .background(Color.clear)
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.large)
        .navigationBarBackButtonHidden(true)
        .toolbarBackground(.hidden, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button {
                    dismiss()
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "chevron.left")
                        Text("Tests")
                    }
                    .foregroundStyle(LuminaV2Theme.accent)
                }
                .accessibilityLabel("Back to Tests")
            }
        }
        .preferredColorScheme(.dark)
    }

    @ViewBuilder
    private func settingsCard(_ title: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.leading, 4)
            VStack(spacing: 0) {
                content()
            }
            .padding(.vertical, 4)
            .luminaCard()
        }
    }

    private func toggleRow(_ title: String, isOn: Binding<Bool>) -> some View {
        Toggle(title, isOn: isOn)
            .tint(LuminaV2Theme.accent)
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .frame(minHeight: 44)
    }

    private func pickerRow<V: Hashable, Content: View>(
        _ title: String,
        selection: Binding<V>,
        @ViewBuilder content: () -> Content
    ) -> some View {
        HStack {
            Text(title)
            Spacer()
            Picker(title, selection: selection) {
                content()
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .tint(LuminaV2Theme.accent)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(minHeight: 44)
    }

    private func labeled(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value)
                .foregroundStyle(.secondary)
                .font(.body.monospaced())
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(minHeight: 44)
    }

    private func buttonRow(_ title: String, systemImage: String, danger: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .frame(maxWidth: .infinity, alignment: .leading)
                .foregroundStyle(danger ? LuminaV2Theme.danger : .primary)
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
                .frame(minHeight: 44)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

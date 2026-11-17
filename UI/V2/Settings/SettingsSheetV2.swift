//
//  SettingsSheetV2.swift
//  Lum1na
//

import SwiftUI

struct SettingsSheetV2: View {
    @Environment(LuminaAppStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        @Bindable var store = store
        NavigationStack {
            List {
                Section("General") {
                    Toggle("Confirm before run", isOn: $store.settings.confirmBeforeRun)
                    Toggle("Pin last summary", isOn: $store.settings.pinLastSummary)
                }

                Section("Tests & Probes") {
                    Picker("Default group", selection: $store.settings.defaultGroup) {
                        ForEach([TestGroup.probes, .taps, .chains, .kernelReads], id: \.self) { g in
                            Text(g.rawValue).tag(g)
                        }
                    }
                    Toggle("Compact badges", isOn: $store.settings.compactBadges)
                }

                Section("Chains") {
                    Toggle("Stop on failure", isOn: $store.settings.stopOnFailure)
                    Toggle("Auto-advance steps", isOn: $store.settings.autoAdvanceSteps)
                }

                Section("Console & Logging") {
                    Toggle("Live stream", isOn: $store.settings.liveStream)
                    LabeledContent("Buffer size", value: "\(store.settings.bufferSize)")
                    Toggle("Millisecond timestamps", isOn: $store.settings.showMilliseconds)
                }

                Section("Lab / Debug") {
                    LabeledContent("Machine", value: store.machine)
                    LabeledContent("Build", value: store.build)
                    LabeledContent("Offset table", value: store.skuTag)
                    LabeledContent("hasKread", value: store.hasKread ? "yes" : "no")
                    Button("Reset session state") {
                        store.resetSession()
                    }
                    .foregroundStyle(LuminaV2Theme.danger)
                }

                Section {
                    Text("Download AI model — lands in a follow-up pass (Qwen3.5-2B GGUF). Not wired in this shell.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("AI")
                }

                Section("Appearance") {
                    Text("Dark-first chrome. CRT is the Console default.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Tests") { dismiss() }
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}

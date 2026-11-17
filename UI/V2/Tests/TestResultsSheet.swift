//
//  TestResultsSheet.swift
//  Lum1na — live console while a test runs.
//

import SwiftUI

struct TestResultsSheet: View {
    @Environment(LuminaAppStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(store.activeRunId ?? "run")
                            .font(.headline.monospaced())
                        HStack(spacing: 6) {
                            Circle()
                                .fill(store.isRunning ? LuminaV2Theme.accent : LuminaV2Theme.ok)
                                .frame(width: 8, height: 8)
                            Text(store.isRunning ? "Running" : "Done")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(store.isRunning ? LuminaV2Theme.accent : LuminaV2Theme.ok)
                        }
                    }
                    Spacer()
                    Button {
                        store.copyToPasteboard(store.exportConsole())
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .frame(width: 44, height: 44)
                    }
                    .accessibilityLabel("Copy output")
                    ShareLink(item: store.exportConsole()) {
                        Image(systemName: "square.and.arrow.up")
                            .frame(width: 44, height: 44)
                    }
                    .accessibilityLabel("Share output")
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
                .padding(.bottom, 12)

                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 4) {
                            ForEach(store.lines) { line in
                                Text(line.formatted)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(color(for: line.level))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(line.id)
                            }
                            Color.clear.frame(height: 1).id("bottom")
                        }
                        .padding(16)
                    }
                    .background(LuminaV2Theme.canvasElevated.opacity(0.9))
                    .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                    .padding(.horizontal, 12)
                    .onChange(of: store.lines.count) { _, _ in
                        guard store.settings.liveStream else { return }
                        withAnimation(LuminaV2Theme.spring(reduceMotion: reduceMotion)) {
                            proxy.scrollTo("bottom", anchor: .bottom)
                        }
                    }
                }

                if store.isRunning {
                    ProgressView(value: max(store.progress, 0.05))
                        .tint(LuminaV2Theme.accent)
                        .padding(.horizontal, 16)
                        .padding(.top, 12)
                }
            }
            .background(LuminaV2Theme.canvas.ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") {
                        dismiss()
                    }
                }
            }
        }
        .presentationDetents([.medium, .large])
        .presentationDragIndicator(.visible)
        .onDisappear {
            if !store.isRunning, store.pinnedSummary != nil {
                // chip remains
            }
        }
    }

    private func color(for level: ConsoleLine.LogLevel) -> Color {
        switch level {
        case .info: return LuminaV2Theme.cyan
        case .success: return LuminaV2Theme.ok
        case .warning: return LuminaV2Theme.amber
        case .error: return LuminaV2Theme.danger
        }
    }
}

//
//  TestResultsSheet.swift
//  Lum1na — inset floating glass card over dimmed list (no nav chrome).
//

import SwiftUI

struct TestResultsSheet: View {
    @Environment(LuminaAppStore.self) private var store
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var displayLines: [ConsoleLine] {
        if let snap = store.viewingSummary?.lineSnapshot, !store.isRunning {
            return snap
        }
        if let snap = store.viewingSummary?.lineSnapshot, store.viewingSummary?.catalogId == store.activeRunId, !store.isRunning {
            return snap
        }
        // Live run
        return store.lines
    }

    private var titleId: String {
        store.viewingSummary?.catalogId ?? store.activeRunId ?? "run"
    }


    var body: some View {
        ZStack {
            Color.black.opacity(0.55)
                .ignoresSafeArea()
                .onTapGesture {
                    if !store.isRunning {
                        store.dismissResultsToChip()
                    }
                }

            VStack(spacing: 0) {
                Spacer(minLength: 48)

                VStack(spacing: 0) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(titleId)
                                .font(.headline.monospaced())
                            HStack(spacing: 6) {
                                Circle()
                                    .fill(store.isRunning ? LuminaV2Theme.accent : statusColor)
                                    .frame(width: 8, height: 8)
                                Text(store.isRunning ? "Running" : (store.viewingSummary?.status.rawValue ?? "Done"))
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(store.isRunning ? LuminaV2Theme.accent : statusColor)
                            }
                        }
                        Spacer()
                        Button {
                            store.copyToPasteboard(store.resultsCopyText())
                        } label: {
                            Image(systemName: "doc.on.doc")
                                .frame(width: 44, height: 44)
                        }
                        .accessibilityLabel("Copy output")
                        Button {
                            store.share(store.resultsCopyText())
                        } label: {
                            Image(systemName: "square.and.arrow.up")
                                .frame(width: 44, height: 44)
                        }
                        .accessibilityLabel("Share output")
                        Button {
                            store.dismissResultsToChip()
                        } label: {
                            Image(systemName: "xmark")
                                .frame(width: 44, height: 44)
                        }
                        .accessibilityLabel("Close")
                        .disabled(store.isRunning)
                        .opacity(store.isRunning ? 0.35 : 1)
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 14)
                    .padding(.bottom, 10)

                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 4) {
                                ForEach(displayLines) { line in
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
                        .frame(maxHeight: 420)
                        .background(LuminaV2Theme.canvasElevated.opacity(0.55))
                        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .padding(.horizontal, 12)
                        .onChange(of: displayLines.count) { _, _ in
                            guard store.settings.liveStream, store.isRunning else { return }
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
                            .padding(.bottom, 14)
                    } else {
                        Color.clear.frame(height: 14)
                    }
                }
                .luminaChromeGlass(cornerRadius: 24, interactive: false)
                .padding(.horizontal, 16)

                Spacer(minLength: LuminaV2Theme.tabBarHeight + 24)
            }
        }
    }

    private var statusColor: Color {
        switch store.viewingSummary?.status {
        case .ok: return LuminaV2Theme.ok
        case .failed: return LuminaV2Theme.danger
        case .gated: return LuminaV2Theme.amber
        case .cancelled: return LuminaV2Theme.pending
        case .none: return LuminaV2Theme.ok
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

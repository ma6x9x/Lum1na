//
//  TestResultsSheet.swift
//  Lum1na — bottom-anchored glass sheet with grabber over dimmed list.
//

import SwiftUI

struct TestResultsSheet: View {
    @Environment(LuminaAppStore.self) private var store
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var displayLines: [ConsoleLine] {
        if let snap = store.viewingSummary?.lineSnapshot, !store.isRunning {
            return snap
        }
        if let snap = store.viewingSummary?.lineSnapshot,
           store.viewingSummary?.catalogId == store.activeRunId,
           !store.isRunning {
            return snap
        }
        return store.lines
    }

    private var titleId: String {
        store.viewingSummary?.catalogId ?? store.activeRunId ?? "run"
    }

    var body: some View {
        ZStack(alignment: .bottom) {
            Color.black.opacity(0.55)
                .ignoresSafeArea()
                .onTapGesture {
                    if !store.isRunning {
                        store.dismissResultsToChip()
                    }
                }

            VStack(spacing: 0) {
                // Grabber
                Capsule(style: .continuous)
                    .fill(Color.white.opacity(0.35))
                    .frame(width: 36, height: 5)
                    .padding(.top, 10)
                    .padding(.bottom, 8)
                    .accessibilityHidden(true)

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
                .padding(.bottom, 10)

                // Inner well — outer 24 / pad 12 / inner 14
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
                        // Snap while streaming — no spring per line.
                        var transaction = Transaction()
                        transaction.disablesAnimations = true
                        withTransaction(transaction) {
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
            // Sit above the floating tab bar + chip clearance so collapse lands on the chip.
            .padding(.bottom, LuminaV2Theme.tabBarHeight + LuminaV2Theme.tabBarBottomInset + 8)
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

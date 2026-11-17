//
//  LuminaRootView.swift
//  Lum1na — v2 4-tab shell root with floating glass pill tab bar.
//

import SwiftUI

struct LuminaRootView: View {
    @State private var store = LuminaAppStore()
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        @Bindable var store = store
        ZStack {
            LuminaV2CircuitCanvas()

            VStack(spacing: 0) {
                Group {
                    switch store.selectedTab {
                    case .tests:
                        TestsTabView()
                    case .chains:
                        ChainsTabView()
                    case .console:
                        ConsoleTabView()
                    case .tools:
                        ToolsTabView()
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)

                LuminaFloatingTabBar(selection: $store.selectedTab)
            }

            // Pinned summary chip — root overlay above tab bar, every tab.
            VStack {
                Spacer()
                if let summary = store.pinnedSummary, !store.showResultsSheet {
                    PinnedSummaryChip(summary: summary) {
                        store.reopenPinnedSummary()
                    }
                    .padding(.horizontal, 16)
                    .padding(.bottom, LuminaV2Theme.tabBarHeight + LuminaV2Theme.tabBarBottomInset + 8)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(LuminaV2Theme.spring(reduceMotion: reduceMotion), value: store.pinnedSummary?.id)
            .animation(LuminaV2Theme.spring(reduceMotion: reduceMotion), value: store.showResultsSheet)

            // Floating results card over dimmed content (no system nav chrome).
            if store.showResultsSheet {
                TestResultsSheet()
                    .transition(.opacity.combined(with: .scale(scale: 0.98)))
                    .zIndex(20)
            }

            // Toast
            VStack {
                Spacer()
                if let toast = store.toastMessage {
                    Text(toast)
                        .font(.footnote.weight(.semibold))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                        .luminaCapsuleGlass()
                        .padding(.bottom, LuminaV2Theme.tabBarHeight + LuminaV2Theme.tabBarBottomInset + 56)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                        .onAppear {
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) {
                                withAnimation(LuminaV2Theme.spring(reduceMotion: reduceMotion)) {
                                    store.toastMessage = nil
                                }
                            }
                        }
                }
            }
        }
        .environment(store)
        .tint(LuminaV2Theme.accent)
        .preferredColorScheme(.dark)
        .animation(LuminaV2Theme.spring(reduceMotion: reduceMotion), value: store.showResultsSheet)
        .animation(LuminaV2Theme.spring(reduceMotion: reduceMotion), value: store.toastMessage)
        .alert(
            "Run \(store.pendingConfirmEntry?.id ?? "test")?",
            isPresented: $store.showRunConfirm
        ) {
            Button("Run", role: .none) { store.confirmPendingRun() }
            Button("Cancel", role: .cancel) { store.cancelPendingRun() }
        } message: {
            Text(store.pendingConfirmEntry.map { CatalogMetadata.meta(for: $0).displayName } ?? "Confirm before run is on.")
        }
        .sheet(isPresented: $store.showHourLogs) {
            HourLogGallery()
        }
        .fullScreenCover(isPresented: $store.showTerminal) {
            MainTerminalPane()
        }
        .sheet(isPresented: $store.showShareSheet) {
            SharePayloadSheet(text: store.shareText ?? "")
        }
    }
}

#Preview {
    LuminaRootView()
}

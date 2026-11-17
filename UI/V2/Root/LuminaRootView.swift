//
//  LuminaRootView.swift
//  Lum1na — v2 4-tab shell root.
//

import SwiftUI

struct LuminaRootView: View {
    @State private var store = LuminaAppStore()
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        TabView(selection: $store.selectedTab) {
            TestsTabView()
                .tabItem { Label("Tests", systemImage: "list.bullet.rectangle") }
                .tag(LuminaAppStore.LuminaTab.tests)

            ChainsTabView()
                .tabItem { Label("Chains", systemImage: "link") }
                .tag(LuminaAppStore.LuminaTab.chains)

            ConsoleTabView()
                .tabItem { Label("Console", systemImage: "chevron.left.forwardslash.chevron.right") }
                .tag(LuminaAppStore.LuminaTab.console)

            ToolsTabView()
                .tabItem { Label("Tools", systemImage: "wrench.and.screwdriver") }
                .tag(LuminaAppStore.LuminaTab.tools)
        }
        .environment(store)
        .tint(LuminaV2Theme.accent)
        .preferredColorScheme(.dark)
        .sheet(isPresented: $store.showSettings) {
            SettingsSheetV2()
                .environment(store)
        }
        .sheet(isPresented: $store.showResultsSheet) {
            TestResultsSheet()
                .environment(store)
        }
        .sheet(isPresented: $store.showHourLogs) {
            HourLogGallery()
        }
        .fullScreenCover(isPresented: $store.showTerminal) {
            MainTerminalPane()
        }
        .overlay(alignment: .bottom) {
            if let toast = store.toastMessage {
                Text(toast)
                    .font(.footnote.weight(.semibold))
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .background(.ultraThinMaterial, in: Capsule())
                    .padding(.bottom, 72)
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
        .animation(LuminaV2Theme.spring(reduceMotion: reduceMotion), value: store.toastMessage)
    }
}

#Preview {
    LuminaRootView()
}

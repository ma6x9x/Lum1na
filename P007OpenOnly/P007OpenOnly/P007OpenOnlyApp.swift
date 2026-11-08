//
//  P007OpenOnlyApp.swift
//  P007OpenOnly
//
//  Created by Kolby Kehler on 8/11/26.
//

import SwiftUI

@main
struct P007OpenOnlyApp: App {
    @StateObject private var engine = LabEngine()
    @StateObject private var browser: FileBrowser
    @StateObject private var clipboard = FileClipboard()
    @StateObject private var bookmarks = Bookmarks()
    @StateObject private var l10n = L10n.shared

    init() {
        // 28951 child mode: runs tests and _exit()s before any UI if argv has --sb-child
        SpawnAttrsProbe.runChildIfNeeded()
        // Disable Metal debug/capture layers BEFORE any Metal object is created
        // This ensures newBufferWithLength: returns raw IOGPUMetalBuffer (has resourceRef)
        setenv("MTL_DEBUG_LAYER", "0", 1)
        setenv("MTL_CAPTURE_ENABLED", "0", 1)
        // Identity + unslid pins into Documents/p007_board.json. hasKread stays NO.
        P007Board.shared().refreshIdentity()
        _browser = StateObject(wrappedValue: FileBrowser(path: Container.documents.path))
    }

    var body: some Scene {
        WindowGroup {
            GlassTierRoot {
                GateView()
                    .environmentObject(engine)
                    .environmentObject(browser)
                    .environmentObject(clipboard)
                    .environmentObject(bookmarks)
                    .environmentObject(l10n)
                    .environment(\.layoutDirection, Lang.resolved.isRTL ? .rightToLeft : .leftToRight)
                    .preferredColorScheme(.dark)
                    .tint(T.accent)
                    .id(Lang.resolved)
            }
        }
    }
}

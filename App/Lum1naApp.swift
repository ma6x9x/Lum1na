import SwiftUI

@main
struct Lum1naApp: App {
    init() {
        TerminalFont.registerIfNeeded()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

import SwiftUI

@main
struct TermLiteApp: App {
    var body: some Scene {
        WindowGroup {
            RootShellView()
                .preferredColorScheme(.dark)
                .tint(.orange)
        }
    }
}

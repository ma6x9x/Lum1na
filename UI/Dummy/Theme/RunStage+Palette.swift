import SwiftUI

extension RunStage {
    /// Stage colour used for its node, bus and console header.
    var color: Color {
        switch self {
        case .kernel: Color(red: 1.0, green: 0.30, blue: 0.42)
        case .patchset: Color(red: 0.30, green: 0.55, blue: 1.0)
        case .sandbox: Color(red: 1.0, green: 0.62, blue: 0.18)
        case .daemon: Color(red: 0.20, green: 0.84, blue: 0.48)
        }
    }
}

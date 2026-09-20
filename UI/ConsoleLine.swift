import SwiftUI

struct ConsoleLine: Identifiable, Equatable {
    let id = UUID()
    let text: String
    let color: Color

    init(text: String, color: Color = .white) {
        self.text = text
        self.color = color
    }
}

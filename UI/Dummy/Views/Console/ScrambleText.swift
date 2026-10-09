import Foundation

/// Glitch/scramble-then-resolve: characters reveal left to right while the
/// next few cells flicker through random glyphs.
enum ScrambleText {
    static let glyphs = Array("▓▒░#%&@$*+=<>/\\01")
    static let charInterval: TimeInterval = 0.011

    /// Resolved prefix and the trailing glitch characters for a line of a given age.
    static func render(_ text: String, age: TimeInterval, seed: Int) -> (resolved: String, glitch: String) {
        let characters = Array(text)
        let shown = max(0, Int(age / charInterval))
        guard shown < characters.count + 3 else { return (text, "") }
        let resolved = String(characters.prefix(min(shown, characters.count)))
        var glitch = ""
        let frame = Int(age / 0.04)
        for k in 0..<3 where shown + k < characters.count {
            let index = Int(HexDump.noise(Double(seed * 31 + k + frame)) * Double(glyphs.count)) % glyphs.count
            glitch.append(glyphs[index])
        }
        return (resolved, glitch)
    }

    static func duration(for text: String) -> TimeInterval {
        Double(text.count + 3) * charInterval
    }
}

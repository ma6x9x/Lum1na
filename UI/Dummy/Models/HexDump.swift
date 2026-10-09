import Foundation

/// Deterministic, meaningless hex rows for the decorative dump block.
enum HexDump {
    static func rows(seed: Int, offset: Int) -> [String] {
        (0..<3).map { r in
            let line = offset + r
            var hex = ""
            var ascii = ""
            for b in 0..<8 {
                let value = Int(noise(Double(seed * 97 + line * 13 + b)) * 256) & 0xFF
                let digits = String(value, radix: 16, uppercase: true)
                hex += (digits.count < 2 ? "0" + digits : digits) + " "
                if value > 64 && value < 123, let scalar = Unicode.Scalar(value) {
                    ascii.append(Character(scalar))
                } else {
                    ascii.append("·")
                }
            }
            let label = line % 100 < 10 ? "0\(line % 100)" : "\(line % 100)"
            return label + "│ " + hex + "│" + ascii
        }
    }

    /// Cheap deterministic 0…1 hash.
    static func noise(_ n: Double) -> Double {
        let x = sin(n * 12.9898 + 78.233) * 43758.5453
        return x - x.rounded(.down)
    }
}

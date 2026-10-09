import Foundation

/// A tiny 5×7 block font (only the letters the banners need) and a builder that
/// turns a word into block-character rows with a dithered `▓` drop shadow.
enum PixelFont {
    static let glyphs: [Character: [String]] = [
        "L": ["#....", "#....", "#....", "#....", "#....", "#....", "#####"],
        "U": ["#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
        "M": ["#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#"],
        "1": ["..#..", ".##..", "#.#..", "..#..", "..#..", "..#..", "#####"],
        "N": ["#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#", "#...#"],
        "A": [".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
        "I": ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "#####"],
        "T": ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."],
        "E": ["#####", "#....", "#....", "####.", "#....", "#....", "#####"],
        "D": ["####.", "#...#", "#...#", "#...#", "#...#", "#...#", "####."]
    ]

    /// Banner rows: `█` letter body, `1` accent body (the numeral), `▓` shadow.
    static func banner(_ word: String) -> [String] {
        let letters = Array(word)
        let cols = letters.count * 6
        let rows = 8
        var grid = Array(repeating: Array(repeating: Character(" "), count: cols), count: rows)
        for (index, letter) in letters.enumerated() {
            guard let glyph = glyphs[letter] else { continue }
            for (r, line) in glyph.enumerated() {
                for (c, cell) in line.enumerated() where cell == "#" {
                    grid[r][index * 6 + c] = letter == "1" ? "1" : "█"
                }
            }
        }
        for r in stride(from: rows - 1, to: 0, by: -1) {
            for c in stride(from: cols - 1, to: 0, by: -1) {
                let above = grid[r - 1][c - 1]
                if grid[r][c] == " " && (above == "█" || above == "1") {
                    grid[r][c] = "▓"
                }
            }
        }
        return grid.map { String($0) }
    }
}

import Foundation

/// Deterministic mulberry32-style generator so the procedural board is
/// identical on every launch (and matches the HTML preview's algorithm).
struct SeededGenerator: RandomNumberGenerator {
    private var state: UInt32

    init(seed: UInt32) { state = seed }

    mutating func next() -> UInt64 {
        UInt64(nextUInt32()) << 32 | UInt64(nextUInt32())
    }

    /// Uniform value in 0..<1.
    mutating func unit() -> Double {
        Double(nextUInt32()) / 4_294_967_296.0
    }

    private mutating func nextUInt32() -> UInt32 {
        state &+= 0x6D2B_79F5
        var t = state
        t = (t ^ (t >> 15)) &* (t | 1)
        t ^= t &+ ((t ^ (t >> 7)) &* (t | 61))
        return t ^ (t >> 14)
    }
}

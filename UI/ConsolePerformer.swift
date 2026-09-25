import Combine
import SwiftUI

/// On-screen theater only. Disk TAP / recovery / PersistentLogStore stay
/// write-through. Never enqueue flavor that claims kread.
@MainActor
final class ConsolePerformer: ObservableObject {
    enum LinePlay {
        case instant
        case typewriter
        case decode
    }

    @Published var finished: [String] = []
    @Published var draft: String = ""
    @Published var blink: Bool = true
    @Published var flashLast: Bool = false

    var reduceMotion: Bool = false

    private var queue: [(String, LinePlay)] = []
    private var consumedHead: UUID?
    private var consumedCount: Int = 0
    private var task: Task<Void, Never>?
    private var blinkTask: Task<Void, Never>?

    private let alphabet: [Character] = Array("01<>[]{}|/\\_-=+*#@$░▒▓")

    func sync(from lines: [ConsoleLine]) {
        if lines.isEmpty {
            reset()
            return
        }
        let head = lines.first?.id
        if head != consumedHead {
            reset()
            consumedHead = head
        }
        while consumedCount < lines.count {
            enqueue(lines[consumedCount].formatted)
            consumedCount += 1
        }
    }

    func reset() {
        task?.cancel()
        task = nil
        queue.removeAll()
        finished.removeAll()
        draft = ""
        flashLast = false
        consumedHead = nil
        consumedCount = 0
        startBlink()
    }

    func enqueue(_ text: String) {
        let play = classify(text)
        queue.append((text, play))
        kick()
    }

    var displayText: String {
        var parts = finished
        if !draft.isEmpty { parts.append(draft) }
        return parts.joined(separator: "\n")
    }

    private func classify(_ text: String) -> LinePlay {
        if reduceMotion { return .instant }
        if text.count > 96 { return .instant }
        if text.contains("===") { return .instant }
        if text.contains("hasKread") || text.contains("hasKwrite")
            || text.contains("kslide=") || text.contains("kbase=") {
            return .decode
        }
        return .typewriter
    }

    private func kick() {
        guard task == nil else { return }
        startBlink()
        task = Task { @MainActor in
            while !Task.isCancelled {
                if reduceMotion || queue.count > 8 {
                    while let (line, _) = pop() {
                        commit(line)
                    }
                    break
                }
                guard let (line, play) = pop() else { break }
                switch play {
                case .instant:
                    commit(line)
                case .typewriter:
                    await typewrite(line)
                case .decode:
                    await decode(line)
                }
            }
            task = nil
            if !queue.isEmpty { kick() }
        }
    }

    private func pop() -> (String, LinePlay)? {
        guard !queue.isEmpty else { return nil }
        return queue.removeFirst()
    }

    private func commit(_ line: String) {
        finished.append(line)
        draft = ""
        flashLast = true
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 80_000_000)
            flashLast = false
        }
    }

    private func splitStamp(_ line: String) -> (String, String) {
        let parts = line.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: false)
        if parts.count >= 3,
           parts[0].count == 10,
           parts[0].contains("-"),
           parts[1].contains(":") {
            let prefix = parts.prefix(3).joined(separator: " ") + " "
            let rest = parts.dropFirst(3).joined(separator: " ")
            return (prefix, rest)
        }
        return ("", line)
    }

    private func typewrite(_ line: String) async {
        let (prefix, body) = splitStamp(line)
        draft = prefix
        if body.hasPrefix("===") {
            commit(line)
            return
        }
        var i = body.startIndex
        while i < body.endIndex {
            if Task.isCancelled { return }
            if reduceMotion || queue.count > 8 {
                commit(line)
                return
            }
            draft = prefix + String(body[..<body.index(after: i)])
            i = body.index(after: i)
            try? await Task.sleep(nanoseconds: 12_000_000)
        }
        if body.hasPrefix("===") || line.contains("===") {
            try? await Task.sleep(nanoseconds: 180_000_000)
        }
        commit(line)
    }

    private func decode(_ line: String) async {
        let (prefix, body) = splitStamp(line)
        let goal = Array(body)
        let maxTick = goal.count + 3
        for tick in 0...maxTick {
            if Task.isCancelled { return }
            if reduceMotion || queue.count > 8 {
                commit(line)
                return
            }
            draft = prefix + decodeFrame(goal: goal, tick: tick)
            try? await Task.sleep(nanoseconds: 32_000_000)
        }
        commit(line)
    }

    private func decodeFrame(goal: [Character], tick: Int) -> String {
        String(goal.enumerated().map { idx, ch in
            if ch == " " { return Character(" ") }
            if tick >= idx + 2 { return ch }
            let pick = abs(idx * 13 + tick * 7) % alphabet.count
            return alphabet[pick]
        })
    }

    private func startBlink() {
        guard blinkTask == nil else { return }
        blinkTask = Task { @MainActor in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 250_000_000)
                blink.toggle()
            }
        }
    }
}

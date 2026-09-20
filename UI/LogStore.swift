//
//  LogStore.swift
//  Lum1na
//
//  Created by Kolby Kehler on 9/19/26.
//


import Foundation
import Combine

class LogStore: ObservableObject {
    @Published var lines: [String] = []
    static let shared = LogStore()
    private let maxLines = 1000
    
    func append(_ message: String) {
        DispatchQueue.main.async {
            let timestamp = self.timestamp()
            let prefixedMessage = message.split(separator: "\n").map { 
                "\(timestamp) \($0)" 
            }.joined(separator: "\n")
            
            self.lines.append(contentsOf: prefixedMessage.split(separator: "\n").map { String($0) })
            
            // Trim old lines
            if self.lines.count > self.maxLines {
                self.lines.removeFirst(self.lines.count - self.maxLines)
            }
        }
    }
    
    func clear() {
        DispatchQueue.main.async {
            self.lines.removeAll()
        }
    }
    
    func saveToFile() {
        let text = lines.joined(separator: "\n")
        let path = NSTemporaryDirectory() + "lumina_log.txt"
        try? text.write(toFile: path, atomically: true, encoding: .utf8)
    }
    
    func loadFromFile() -> [String] {
        let path = NSTemporaryDirectory() + "lumina_log.txt"
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            return ["No recovery log found"]
        }
        return text.components(separatedBy: .newlines)
    }
    
    private func timestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return "[\(formatter.string(from: Date()))]"
    }
}
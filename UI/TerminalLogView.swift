//
//  TerminalLogView.swift
//  Lum1na
//
//  Created by Kolby Kehler on 9/19/26.
//


import SwiftUI

struct TerminalLogView: View {
    @ObservedObject var logStore: LogStore
    @State private var autoScroll = true
    
    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(logStore.lines.enumerated()), id: \.offset) { index, line in
                        Text(line)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(colorForLine(line))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .id(index)
                    }
                }
                .padding(8)
            }
            .background(Color.black)
            .onChange(of: logStore.lines.count) { _ in
                if autoScroll, let last = logStore.lines.indices.last {
                    withAnimation(.easeOut(duration: 0.1)) {
                        proxy.scrollTo(last, anchor: .bottom)
                    }
                }
            }
        }
    }
    
    private func colorForLine(_ line: String) -> Color {
        if line.contains("[+]") || line.contains("SUCCESS") { return .green }
        if line.contains("[-]") || line.contains("FAILED") { return .red }
        if line.contains("[!]") || line.contains("WARNING") { return .yellow }
        if line.contains("[*]") { return .cyan }
        return .white
    }
}
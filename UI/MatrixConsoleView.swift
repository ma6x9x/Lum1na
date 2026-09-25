//
//  MatrixConsoleView.swift
//  Lum1na
//
//  P007-style: one monospaced stream of already-stamped lines.
//  Theater (typewriter/decode) is display-only. Disk TAP is untouched.
//

import SwiftUI

struct MatrixConsoleView: View {
    @ObservedObject private var manager = ExploitManager.shared
    @StateObject private var performer = ConsolePerformer()
    @State private var autoScroll = true
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var truthDump: String {
        manager.lines.map(\.formatted).joined(separator: "\n")
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            ScrollViewReader { proxy in
                ScrollView(.vertical, showsIndicators: true) {
                    consoleBody
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(performer.flashLast ? .white : Color(hex: "#E2E8F0"))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                        .id("console-bottom")
                }
                .onChange(of: manager.lines.count) { _ in
                    performer.reduceMotion = reduceMotion
                    performer.sync(from: manager.lines)
                    if autoScroll {
                        withAnimation(.easeOut(duration: 0.08)) {
                            proxy.scrollTo("console-bottom", anchor: .bottom)
                        }
                    }
                }
                .onChange(of: performer.draft) { _ in
                    if autoScroll {
                        proxy.scrollTo("console-bottom", anchor: .bottom)
                    }
                }
                .onAppear {
                    performer.reduceMotion = reduceMotion
                    performer.sync(from: manager.lines)
                }
                .onChange(of: reduceMotion) { _ in
                    performer.reduceMotion = reduceMotion
                }
            }
        }
        .frame(minHeight: LayoutConstants.consoleMinHeight)
        .luminaGlassRect(26, interactive: false)
    }

    @ViewBuilder
    private var consoleBody: some View {
        let finished = performer.finished.joined(separator: "\n")
        let cursor = performer.blink ? "█" : " "
        let draft = performer.draft
        let idle = manager.lines.isEmpty && finished.isEmpty && draft.isEmpty
        if idle {
            Text("\(LabTime.militaryNow()) [*] console idle")
        } else if draft.isEmpty {
            Text(finished.isEmpty ? truthDump : finished)
        } else {
            Text(finished.isEmpty ? (draft + cursor) : (finished + "\n" + draft + cursor))
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "terminal.fill")
                .font(.system(size: 10))
                .foregroundColor(Color(hex: "#64748B"))
            Text("console")
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(Color(hex: "#64748B"))
            Text("\(manager.lines.count)")
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(Color(hex: "#475569"))
            Spacer()
            Button {
                autoScroll.toggle()
            } label: {
                Text(autoScroll ? "LIVE" : "HOLD")
                    .font(.system(.caption2, design: .monospaced, weight: .bold))
                    .foregroundColor(autoScroll ? Color(hex: "#10B981") : Color(hex: "#FBBF24"))
            }
            Button {
                UIPasteboard.general.string = truthDump
            } label: {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 12))
                    .foregroundColor(Color(hex: "#64748B"))
            }
            Button {
                manager.clearConsole()
                performer.reset()
            } label: {
                Text("CLEAR")
                    .font(.system(.caption2, design: .monospaced, weight: .bold))
                    .foregroundColor(Color(hex: "#64748B"))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(hex: "#0F0F14"))
    }
}

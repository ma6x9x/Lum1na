//
//  MatrixConsoleView.swift
//  Lum1na
//
//  P007-style: one monospaced stream of already-stamped lines.
//  Do not add a second timestamp column — ConsoleLine.formatted already
//  has `yyyy-MM-dd HH:mm:ss z`.
//

import SwiftUI

struct MatrixConsoleView: View {
    @ObservedObject private var manager = ExploitManager.shared
    @State private var autoScroll = true

    private var dump: String {
        manager.lines.map(\.formatted).joined(separator: "\n")
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            ScrollViewReader { proxy in
                ScrollView(.vertical, showsIndicators: true) {
                    Text(dump.isEmpty ? "\(LabTime.militaryNow()) [*] console idle" : dump)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(Color(hex: "#E2E8F0"))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                        .id("console-bottom")
                }
                .onChange(of: manager.lines.count) { _ in
                    if autoScroll {
                        withAnimation(.easeOut(duration: 0.08)) {
                            proxy.scrollTo("console-bottom", anchor: .bottom)
                        }
                    }
                }
            }
        }
        .frame(minHeight: 220)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(hex: "#0A0A0F"))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color(hex: "#1E293B"), lineWidth: 1)
                )
        )
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
                UIPasteboard.general.string = dump
            } label: {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 12))
                    .foregroundColor(Color(hex: "#64748B"))
            }
            Button {
                manager.clearConsole()
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

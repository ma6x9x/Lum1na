//
//  ConsolePerformer.swift
//  Lum1na
//
//  Tag-colored console: [P0xx] blue, [*] blue, [+] green, [-] red, [!] yellow.
//  Filter, auto-scroll, Dynamic Type, dark-mode safe.
//

import SwiftUI

struct ConsolePerformer: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @State private var filterText = ""
    @State private var autoScroll = true

    private var filtered: [LogEntry] {
        guard !filterText.isEmpty else { return viewModel.consoleLogs }
        return viewModel.consoleLogs.filter {
            $0.message.localizedCaseInsensitiveContains(filterText) ||
            $0.tag.localizedCaseInsensitiveContains(filterText)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                Toggle(isOn: $autoScroll) {
                    Image(systemName: "arrow.down.circle").font(.caption)
                }.toggleStyle(.button)
                Spacer()
                Text("\(filtered.count) logs").font(.caption).foregroundColor(.secondary)
                Button { viewModel.clearLogs() } label: { Image(systemName: "trash").font(.caption) }
                    .disabled(viewModel.consoleLogs.isEmpty)
            }
            .padding(.horizontal).padding(.vertical, 8)

            HStack {
                Image(systemName: "magnifyingglass").foregroundColor(.secondary)
                TextField("Filter (tag or text)…", text: $filterText).font(.subheadline)
                if !filterText.isEmpty {
                    Button { filterText = "" } label: { Image(systemName: "xmark.circle.fill").foregroundColor(.secondary) }
                }
            }
            .padding(8)
            .background(Color(.tertiarySystemBackground))

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(filtered) { entry in
                            LogLineView(entry: entry).id(entry.id)
                        }
                    }
                    .padding(.horizontal).padding(.vertical, 8)
                }
                .onChange(of: filtered.count) { _, _ in
                    if autoScroll, let last = filtered.last {
                        withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
            }
        }
        .background(Color(.systemBackground))
    }
}

struct LogLineView: View {
    let entry: LogEntry
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(entry.timestampText)
                .font(.caption2.monospaced()).foregroundColor(.secondary)
                .frame(width: 56, alignment: .leading)
            Text("[\(entry.tag)]")
                .font(.caption.bold().monospaced())
                .foregroundColor(entry.color)
                .frame(minWidth: 76, alignment: .leading)
            Text(entry.message)
                .font(.caption)
                .foregroundColor(.primary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(entry.tag): \(entry.message)")
    }
}

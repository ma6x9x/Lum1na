//
//  ContentView.swift
//  Lum1na
//
//  Self-contained main UI: board panel, strategy picker, stage list,
//  chain diagram, console, board details. Dark-mode safe (semantic colors).
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                BoardPanelView(viewModel: viewModel)
                    .padding(.horizontal)
                    .padding(.top, 8)

                TabView {
                    StagesView(viewModel: viewModel)
                        .tabItem { Label("Stages", systemImage: "list.bullet.rectangle") }
                    ConsoleView(viewModel: viewModel)
                        .tabItem { Label("Console", systemImage: "terminal") }
                    BoardDetailsView(viewModel: viewModel)
                        .tabItem { Label("Board", systemImage: "cpu") }
                }
            }
            .navigationTitle("Lum1na")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { viewModel.clearLogs() } label: { Image(systemName: "trash") }
                        .disabled(viewModel.consoleLogs.isEmpty)
                }
            }
        }
    }
}

// MARK: - Board Panel

struct BoardPanelView: View {
    @ObservedObject var viewModel: Lum1naViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "cpu")
                Text("Lum1naBoard").font(.headline)
                Spacer()
                HStack(spacing: 6) {
                    Circle()
                        .fill(viewModel.board.hasLeak ? Color.green : Color.red)
                        .frame(width: 8, height: 8)
                    Text(viewModel.board.hasLeak ? "LEAKED" : "NO LEAK")
                        .font(.caption.bold())
                        .foregroundColor(viewModel.board.hasLeak ? .green : .red)
                }
                .padding(.horizontal, 10).padding(.vertical, 4)
                .background((viewModel.board.hasLeak ? Color.green : Color.red).opacity(0.12))
                .cornerRadius(8)
            }

            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                BoardStatItem(label: "hasKread",
                              value: viewModel.board.hasKread ? "YES" : "NO",
                              warn: !viewModel.board.hasKread)
                BoardStatItem(label: "hasKwrite",
                              value: viewModel.board.hasKwrite ? "YES" : "NO",
                              warn: !viewModel.board.hasKwrite)
                BoardStatItem(label: "kslide",
                              value: String(format: "0x%llx", viewModel.board.kslide),
                              warn: viewModel.board.kslide == 0)
                BoardStatItem(label: "kbase",
                              value: String(format: "0x%llx", viewModel.board.kbase),
                              warn: viewModel.board.kbase == 0)
            }

            if !viewModel.board.hasLeak && viewModel.groomedPairCount > 0 {
                Label("No kernel-side leakage — overflow did not reach driver",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundColor(.red)
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.red.opacity(0.1)).cornerRadius(8)
            }
            if viewModel.board.hasKRW {
                Label("KRW primitives established", systemImage: "checkmark.shield.fill")
                    .font(.caption).foregroundColor(.green)
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.green.opacity(0.1)).cornerRadius(8)
            }
        }
        .padding()
        .background(Color(.secondarySystemGroupedBackground))
        .cornerRadius(16)
    }
}

struct BoardStatItem: View {
    let label: String
    let value: String
    var warn: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption).foregroundColor(.secondary)
            Text(value)
                .font(.system(.body, design: .monospaced).weight(.semibold))
                .foregroundColor(warn ? .red : .primary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Stages Tab

struct StagesView: View {
    @ObservedObject var viewModel: Lum1naViewModel

    var body: some View {
        VStack(spacing: 0) {
            Picker("Strategy", selection: $viewModel.activeStrategy) {
                ForEach(Strategy.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .padding()

            switch viewModel.activeStrategy {
            case .aneChain: aneChainView
            case .p022:     p022View
            case .oracle:   oracleView
            }
        }
        .background(Color(.systemGroupedBackground))
    }

    private var aneChainView: some View {
        ScrollView {
            VStack(spacing: 12) {
                ChainDiagramView(viewModel: viewModel)
                StageRow(code: "P044", name: "Hole-Victim Groom",
                         detail: "2048 pairs → free holes → ANE fire → KRW scan",
                         status: viewModel.p044Status) { viewModel.runP044Chain() }
                StageRow(code: "P059", name: "ANEDirectIn",
                         detail: "Direct ANE selector 2 — bypasses CoreML x_189 wall",
                         status: viewModel.aneDirectInStatus) { viewModel.runANEDirectIn() }
                StageRow(code: "P061", name: "IOGPU 64788 Race",
                         detail: "replace_backing_bytes UAF — 23F77 verified pins",
                         status: viewModel.p061Status) { viewModel.runP061() }
            }
            .padding(.vertical)
        }
    }

    private var p022View: some View {
        ScrollView {
            VStack(spacing: 12) {
                StageRow(code: "P022", name: "shared_region",
                         detail: "syscall 536 sf_fd=-1 — ret 0 = direct KRW path",
                         status: viewModel.p022Status) { viewModel.runP022Probes() }

                VStack(alignment: .leading, spacing: 8) {
                    Text("Probe Details").font(.headline)
                    ForEach(viewModel.p022ProbeResults) { r in
                        HStack {
                            Image(systemName: r.succeeded ? "checkmark.circle.fill"
                                                          : "xmark.circle.fill")
                                .foregroundColor(r.succeeded ? .green : .red)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Probe \(r.name)").font(.subheadline.bold())
                                Text(r.detail).font(.caption).foregroundColor(.secondary)
                            }
                            Spacer()
                            Text("ret=\(r.ret) errno=\(r.errnoValue)")
                                .font(.caption.monospaced())
                                .foregroundColor(r.succeeded ? .green : .secondary)
                        }
                        .padding(.vertical, 4)
                    }
                    if viewModel.p022ProbeResults.isEmpty {
                        Text("No probe results yet.")
                            .font(.caption).foregroundColor(.secondary)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.secondarySystemGroupedBackground))
                .cornerRadius(12)
                .padding(.horizontal)
            }
            .padding(.vertical)
        }
    }

    private var oracleView: some View {
        ScrollView {
            VStack(spacing: 12) {
                StageRow(code: "P060", name: "kmsg 3072 Oracle",
                         detail: "Shape-O land detection for CVE-2026-43748 (992B OOB)",
                         status: viewModel.kmsgOracleStatus) { viewModel.runKmsgOracle() }
                StageRow(code: "P062", name: "Stale-Entry Oracle",
                         detail: "64788 kalloc.256 — 1×65535 trigger, zero-payload safe",
                         status: viewModel.p062Status) { viewModel.runP062() }

                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("P060 corrupted pairs").font(.subheadline.bold())
                        Spacer()
                        Text("\(viewModel.corruptedPairCount)")
                            .font(.title3.bold())
                            .foregroundColor(viewModel.corruptedPairCount > 0 ? .green : .orange)
                    }
                    Divider()
                    HStack {
                        Text("P062 stale hits (0xe0002be)").font(.subheadline.bold())
                        Spacer()
                        Text("\(viewModel.p062StaleHits)")
                            .font(.title3.bold())
                            .foregroundColor(viewModel.p062StaleHits > 0 ? .green : .orange)
                    }
                }
                .padding()
                .background(Color(.secondarySystemGroupedBackground))
                .cornerRadius(12)
                .padding(.horizontal)
            }
            .padding(.vertical)
        }
    }
}

// MARK: - Stage Row + Chip

struct StageRow: View {
    let code: String
    let name: String
    let detail: String
    let status: StageStatus
    let onRun: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Text(code)
                .font(.caption.bold().monospaced())
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(Color.accentColor.opacity(0.15))
                .foregroundColor(.accentColor).cornerRadius(6)

            VStack(alignment: .leading, spacing: 3) {
                Text(name).font(.subheadline.bold())
                Text(detail).font(.caption).foregroundColor(.secondary)
            }
            Spacer()
            StatusChip(status: status)
            Button(action: onRun) {
                Image(systemName: "play.fill")
                    .font(.caption)
                    .padding(8)
                    .background(Color.accentColor.opacity(0.15))
                    .foregroundColor(.accentColor)
                    .clipShape(Circle())
            }
            .buttonStyle(.plain)
            .disabled(status == .running)
            .accessibilityLabel("Run \(code)")
        }
        .padding()
        .background(Color(.secondarySystemGroupedBackground))
        .cornerRadius(12)
        .padding(.horizontal)
    }
}

struct StatusChip: View {
    let status: StageStatus

    var body: some View {
        Group {
            switch status {
            case .fail(let e, let kr):
                VStack(alignment: .trailing, spacing: 2) {
                    chip("FAIL", .red)
                    Text("errno=\(e) kr=\(kr)")
                        .font(.caption2.monospaced())
                        .foregroundColor(.red.opacity(0.8))
                }
            default:
                chip(status.displayText, status.chipColor)
            }
        }
    }

    private func chip(_ text: String, _ color: Color) -> some View {
        Text(text).font(.caption.bold())
            .padding(.horizontal, 10).padding(.vertical, 4)
            .background(color.opacity(0.15)).foregroundColor(color).cornerRadius(8)
    }
}

// MARK: - Chain Diagram

struct ChainDiagramView: View {
    @ObservedObject var viewModel: Lum1naViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Chain Diagram").font(.headline).padding(.horizontal)
            VStack(spacing: 0) {
                chainRow("square.stack.3d.up", "Groom",
                         "\(viewModel.groomedPairCount) pairs", viewModel.groomState)
                connector()
                chainRow("flame", "ANE Fire", "CVE-2026-43748", viewModel.aneFireState)
                connector()
                chainRow("magnifyingglass", "Pair Scan", "victim scan",
                         viewModel.pairScanState)
                connector()
                chainRow("lock.open", "KRW", "kernel read/write", viewModel.krwChainState)
            }
            .padding()
            .background(Color(.secondarySystemGroupedBackground))
            .cornerRadius(12)
            .padding(.horizontal)
        }
    }

    @ViewBuilder private func chainRow(_ icon: String, _ title: String,
                                       _ detail: String, _ state: ChainState) -> some View {
        HStack(spacing: 12) {
            Image(systemName: state.iconName)
                .font(.title3).foregroundColor(state.color).frame(width: 24)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.subheadline.bold())
                Text(detail).font(.caption).foregroundColor(.secondary)
            }
            Spacer()
        }.padding(.vertical, 4)
    }

    private func connector() -> some View {
        Rectangle().fill(Color.secondary.opacity(0.3))
            .frame(width: 2, height: 14).padding(.leading, 11)
    }
}

// MARK: - Console

struct ConsoleView: View {
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
            }
            .padding(.horizontal).padding(.vertical, 8)

            HStack {
                Image(systemName: "magnifyingglass").foregroundColor(.secondary)
                TextField("Filter (tag or text)…", text: $filterText)
                    .font(.subheadline)
                if !filterText.isEmpty {
                    Button { filterText = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundColor(.secondary)
                    }
                }
            }
            .padding(8)
            .background(Color(.tertiarySystemBackground))

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(filtered) { entry in
                            logLine(entry).id(entry.id)
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

    @ViewBuilder private func logLine(_ entry: LogEntry) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(entry.timeText)
                .font(.caption2.monospaced()).foregroundColor(.secondary)
                .frame(width: 56, alignment: .leading)
            Text("[\(entry.tag)]")
                .font(.caption.bold().monospaced())
                .foregroundColor(entry.color)
                .frame(minWidth: 90, alignment: .leading)
            Text(entry.message)
                .font(.caption).foregroundColor(.primary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Board Details

struct BoardDetailsView: View {
    @ObservedObject var viewModel: Lum1naViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("Heap Leaks").font(.headline)
                        Spacer()
                        Text("\(viewModel.board.leaks.count) found")
                            .font(.caption).foregroundColor(.secondary)
                    }
                    if viewModel.board.leaks.isEmpty {
                        Text("No heap leaks recorded.")
                            .font(.caption).foregroundColor(.secondary)
                    } else {
                        VStack(spacing: 0) {
                            HStack {
                                Text("VA").font(.caption.bold())
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                Text("SOURCE").font(.caption.bold())
                                    .frame(width: 110, alignment: .leading)
                                Text("KIND").font(.caption.bold())
                                    .frame(width: 70, alignment: .leading)
                            }
                            .padding(.vertical, 6)
                            ForEach(viewModel.board.leaks) { leak in
                                Divider()
                                HStack {
                                    Text(leak.va).font(.caption.monospaced())
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                    Text(leak.source).font(.caption)
                                        .frame(width: 110, alignment: .leading)
                                    Text(leak.kind).font(.caption)
                                        .frame(width: 70, alignment: .leading)
                                }
                                .padding(.vertical, 6)
                            }
                        }
                        .background(Color(.tertiarySystemGroupedBackground))
                        .cornerRadius(8)
                    }
                }
                .padding()
                .background(Color(.secondarySystemGroupedBackground))
                .cornerRadius(12).padding(.horizontal)
            }
            .padding(.vertical)
        }
    }
}

#Preview {
    ContentView()
}

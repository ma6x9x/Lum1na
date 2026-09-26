//
//  ContentView.swift
//  Lum1na
//
//  Board panel + tabs (Stages / Console / Board). Dark-mode safe via semantic colors.
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                BoardPanelView(viewModel: viewModel)
                    .padding(.horizontal).padding(.top, 8)

                TabView {
                    ExploitStageSelector(viewModel: viewModel)
                        .tabItem { Label("Stages", systemImage: "list.bullet.rectangle") }
                    ConsolePerformer(viewModel: viewModel)
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
                        .fill(viewModel.isKernelLeakDetected ? Color.green : Color.red)
                        .frame(width: 8, height: 8)
                    Text(viewModel.isKernelLeakDetected ? "LEAKED" : "NO LEAK")
                        .font(.caption.bold())
                        .foregroundColor(viewModel.isKernelLeakDetected ? .green : .red)
                }
                .padding(.horizontal, 10).padding(.vertical, 4)
                .background((viewModel.isKernelLeakDetected ? Color.green : Color.red).opacity(0.12))
                .cornerRadius(8)
            }

            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                BoardStatItem(label: "hasKread",
                              value: viewModel.board.hasKread ? "YES" : "NO",
                              highlightZero: !viewModel.board.hasKread)
                BoardStatItem(label: "hasKwrite",
                              value: viewModel.board.hasKwrite ? "YES" : "NO",
                              highlightZero: !viewModel.board.hasKwrite)
                BoardStatItem(label: "kslide",
                              value: String(format: "0x%llx", viewModel.board.kslide),
                              highlightZero: viewModel.board.kslide == 0)
                BoardStatItem(label: "kbase",
                              value: String(format: "0x%llx", viewModel.board.kbase),
                              highlightZero: viewModel.board.kbase == 0)
            }

            if !viewModel.isKernelLeakDetected && viewModel.groomedPairCount > 0 {
                Label("No kernel-side leakage — overflow did not reach driver",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundColor(.red)
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.red.opacity(0.1)).cornerRadius(8)
            }
            if viewModel.hasKRW {
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
    var highlightZero: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption).foregroundColor(.secondary)
            Text(value)
                .font(.system(.body, design: .monospaced).weight(.semibold))
                .foregroundColor(highlightZero ? .red : .primary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Board Details (leak table + raw JSON)

struct BoardDetailsView: View {
    @ObservedObject var viewModel: Lum1naViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("Heap Leaks").font(.headline)
                        Spacer()
                        Text("\(viewModel.board.heapLeaks.count) found")
                            .font(.caption).foregroundColor(.secondary)
                    }
                    if viewModel.board.heapLeaks.isEmpty {
                        Text("No heap leaks recorded.")
                            .font(.caption).foregroundColor(.secondary)
                    } else {
                        VStack(spacing: 0) {
                            HStack {
                                Text("VA").font(.caption.bold()).frame(maxWidth: .infinity, alignment: .leading)
                                Text("SOURCE").font(.caption.bold()).frame(width: 100, alignment: .leading)
                                Text("KIND").font(.caption.bold()).frame(width: 70, alignment: .leading)
                            }
                            .padding(.vertical, 6)
                            ForEach(viewModel.board.heapLeaks) { leak in
                                Divider()
                                HStack {
                                    Text(leak.va).font(.caption.monospaced())
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                    Text(leak.source).font(.caption).frame(width: 100, alignment: .leading)
                                    Text(leak.kind).font(.caption).frame(width: 70, alignment: .leading)
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

                VStack(alignment: .leading, spacing: 8) {
                    Text("Raw Board JSON").font(.headline)
                    if let data = try? JSONEncoder().encode(viewModel.board),
                       let s = String(data: data, encoding: .utf8) {
                        Text(s).font(.caption.monospaced()).textSelection(.enabled)
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.secondarySystemGroupedBackground))
                .cornerRadius(12).padding(.horizontal)
            }
            .padding(.vertical)
        }
    }
}

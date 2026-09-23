//
//  ContentView.swift
//  Updated with All Exploits menu
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()
    @State private var showingStageTester = false
    @State private var showingAllExploits = false
    
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            
            VStack(spacing: 12) {
                // Header
                Text("Lum1na")
                    .font(.largeTitle)
                    .foregroundColor(.white)
                    .padding(.top, 20)
                
                Text(viewModel.exploitState.description)
                    .font(.headline)
                    .foregroundColor(statusColor)
                
                // Console with Copy button
                consoleSection
                
                Spacer(minLength: 20)
                
                // Stage buttons
                stageButtonsSection
                    .padding(.bottom, 10)
                
                // Full chain button
                Button("Execute Full Chain") {
                    Task { await viewModel.executeStage("Full Chain") }
                }
                .font(.headline)
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.blue.opacity(0.3))
                .cornerRadius(10)
                .disabled(viewModel.isRunning)
                
                // All Exploits button
                Button("All Exploits ▼") {
                    showingAllExploits = true
                }
                .font(.subheadline)
                .foregroundColor(.cyan)
                .padding(.bottom, 10)
            }
            .padding(.horizontal)
        }
        .sheet(isPresented: $showingAllExploits) {
            AllExploitsView(viewModel: viewModel)
        }
    }
    
    // MARK: - Console Section with Copy
    private var consoleSection: some View {
        VStack(spacing: 4) {
            HStack {
                Text("Console")
                    .font(.caption)
                    .foregroundColor(.gray)
                Spacer()
                Button(action: {
                    UIPasteboard.general.string = viewModel.consoleText
                }) {
                    Image(systemName: "doc.on.doc")
                        .font(.caption)
                        .foregroundColor(.cyan)
                }
                Button(action: { viewModel.clearConsole() }) {
                    Image(systemName: "trash")
                        .font(.caption)
                        .foregroundColor(.red)
                        .padding(.leading, 8)
                }
            }
            .padding(.horizontal, 8)
            
            ScrollView {
                Text(viewModel.consoleText)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: 280) // Increased height
            .background(Color.black.opacity(0.5))
            .cornerRadius(8)
        }
    }
    
    // MARK: - Stage Buttons
    private var stageButtonsSection: some View {
        HStack(spacing: 8) {
            StageButton(title: "KERNEL", color: .blue) {
                Task { await viewModel.executeStage("KERNEL") }
            }
            StageButton(title: "SANDBOX", color: .orange) {
                Task { await viewModel.executeStage("SANDBOX") }
            }
            StageButton(title: "DAEMON", color: .purple) {
                Task { await viewModel.executeStage("DAEMON") }
            }
            StageButton(title: "PATCH", color: .red) {
                Task { await viewModel.executeStage("PATCHSET") }
            }
        }
    }
    
    private var statusColor: Color {
        switch viewModel.exploitState {
        case .success: return .green
        case .failed: return .red
        case .idle: return .gray
        default: return .blue
        }
    }
}

// MARK: - Stage Button
struct StageButton: View {
    let title: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.caption)
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .frame(height: 50)
                .background(color.opacity(0.3))
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(color, lineWidth: 1)
                )
        }
    }
}

// MARK: - All Exploits View
struct AllExploitsView: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @Environment(\.dismiss) var dismiss
    
    let exploits = [
        ("P044 ANE 254-Input", "KERNEL", "brain"),
        ("CVE-2026-65343 AKS", "SANDBOX", "lock.shield"),
        ("P035 AVE Wrap", "KERNEL", "video"),
        ("P051 APFS Xattr", "SANDBOX", "folder"),
        ("P054 APFS Reap", "DAEMON", "archivebox"),
    ]
    
    var body: some View {
        NavigationView {
            List {
                Section(header: Text("Individual Exploits")) {
                    ForEach(exploits, id: \.0) { exploit in
                        Button {
                            Task {
                                await viewModel.executeStage(exploit.1)
                                dismiss()
                            }
                        } label: {
                            HStack {
                                Image(systemName: exploit.2)
                                    .foregroundColor(.blue)
                                VStack(alignment: .leading) {
                                    Text(exploit.0)
                                        .font(.headline)
                                    Text("Stage: \(exploit.1)")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                }
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .foregroundColor(.gray)
                            }
                        }
                    }
                }
                
                Section(header: Text("Debug")) {
                    Button("Export Full Log") {
                        UIPasteboard.general.string = viewModel.exportFullDebugLog()
                    }
                    Button("Clear Console") {
                        viewModel.clearConsole()
                    }
                    .foregroundColor(.red)
                }
            }
            .navigationTitle("All Exploits")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

//
//  ContentView.swift
//  Lum1na
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()
    @State private var showMoreProbes = false
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Console Output
                consoleView
                
                Divider()
                
                // Control Panel
                controlPanel
            }
            .navigationTitle("Lum1na")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button(action: { viewModel.clearConsole() }) {
                            Label("Clear Log", systemImage: "trash")
                        }
                        Button(action: { viewModel.showRecoveredLog() }) {
                            Label("Recovered Log", systemImage: "doc.text.magnifyingglass")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .sheet(isPresented: $viewModel.showRecoveredLogSheet) {
                RecoveredLogView(content: viewModel.recoveredLogContent)
            }
            .sheet(isPresented: $showMoreProbes) {
                ProbesListView(viewModel: viewModel)
            }
        }
    }
    
    // MARK: - Console View
    
    private var consoleView: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(viewModel.consoleBuffer.indices, id: \.self) { index in
                        let line = viewModel.consoleBuffer[index]
                        ConsoleLineView(line: line)
                            .id(index)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(.secondarySystemBackground))
            .onChange(of: viewModel.consoleBuffer.count) { _ in
                if let last = viewModel.consoleBuffer.indices.last {
                    withAnimation {
                        proxy.scrollTo(last, anchor: .bottom)
                    }
                }
            }
        }
    }
    
    // MARK: - Control Panel
    
    private var controlPanel: some View {
        VStack(spacing: 12) {
            // Device Info
            deviceInfoRow
            
            Divider()
            
            // Hot Buttons
            hotButtonsRow
            
            Divider()
            
            // Status & Actions
            statusAndActionsRow
            
            // Running Indicator
            if viewModel.isRunning {
                runningIndicator
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(.systemBackground))
    }
    
    // MARK: - Device Info
    
    private var deviceInfoRow: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(viewModel.deviceInfo?.machine ?? "Unknown")
                    .font(.system(size: 13, weight: .semibold))
                Text("iOS \(viewModel.deviceInfo?.version ?? "?")")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            HStack(spacing: 4) {
                Circle()
                    .fill(viewModel.statusColor)
                    .frame(width: 6, height: 6)
                Text(viewModel.statusText)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(viewModel.statusColor)
            }
        }
    }
    
    // MARK: - Hot Buttons
    
    private var hotButtonsRow: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                HotButton(
                    title: "AKS KASLR",
                    icon: "location.circle",
                    color: .blue,
                    action: { viewModel.testAKS() },
                    disabled: viewModel.isRunning
                )
                
                HotButton(
                    title: "PAC Bypass",
                    icon: "key.fill",
                    color: .purple,
                    action: { viewModel.testPACBypass() },
                    disabled: viewModel.isRunning
                )
            }
            
            HStack(spacing: 8) {
                HotButton(
                    title: "OOB Write",
                    icon: "pencil.circle",
                    color: .orange,
                    action: { viewModel.testOOBWrite() },
                    disabled: viewModel.isRunning
                )
                
                HotButton(
                    title: "APFS",
                    icon: "archivebox",
                    color: .green,
                    action: { viewModel.testAPFS() },
                    disabled: viewModel.isRunning,
                    isRisky: true
                )
            }
            
            Button(action: { viewModel.startFullChain() }) {
                Text("Full Chain")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .background(
                        LinearGradient(
                            colors: [.pink, .purple],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    )
                    .cornerRadius(10)
            }
            .disabled(viewModel.isRunning)
        }
    }
    
    // MARK: - Status & Actions
    
    private var statusAndActionsRow: some View {
        HStack(spacing: 12) {
            Button {
                viewModel.clearConsole()
            } label: {
                Image(systemName: "trash")
            }
            .buttonStyle(.bordered)
            .disabled(viewModel.isRunning)
            
            Button {
                viewModel.showRecoveredLog()
            } label: {
                Image(systemName: "doc.text.magnifyingglass")
            }
            .buttonStyle(.bordered)
            .disabled(viewModel.isRunning)
            
            Spacer()
            
            Button {
                showMoreProbes = true
            } label: {
                Label("More", systemImage: "list.bullet")
            }
            .buttonStyle(.borderedProminent)
            .tint(.indigo)
            .disabled(viewModel.isRunning)
        }
    }
    
    // MARK: - Running Indicator
    
    private var runningIndicator: some View {
        HStack(spacing: 12) {
            ProgressView()
                .controlSize(.small)
            
            Text(viewModel.exploitState.description)
                .font(.caption)
                .fontWeight(.medium)
            
            Spacer()
            
            Button {
                viewModel.reset()
            } label: {
                Label("Cancel", systemImage: "xmark")
                    .font(.caption)
            }
            .buttonStyle(.borderedProminent)
            .tint(.orange)
            .controlSize(.small)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(Color.orange.opacity(0.1))
        .cornerRadius(8)
    }
}

// MARK: - Console Line View

struct ConsoleLineView: View {
    let line: String
    
    var body: some View {
        HStack(alignment: .top, spacing: 4) {
            // Parse level from line
            let level = parseLevel(from: line)
            let message = parseMessage(from: line)
            
            Image(systemName: iconForLevel(level))
                .font(.caption2)
                .foregroundColor(colorForLevel(level))
                .frame(width: 16)
            
            Text(message)
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(colorForLevel(level))
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    
    private func parseLevel(from line: String) -> String {
        if line.contains("[ERROR]") { return "ERROR" }
        if line.contains("[SUCCESS]") { return "SUCCESS" }
        if line.contains("[RECOVERY]") { return "RECOVERY" }
        if line.contains("[WARN]") { return "WARN" }
        return "INFO"
    }
    
    private func parseMessage(from line: String) -> String {
        // Extract message after timestamp and level
        let components = line.components(separatedBy: "] ")
        return components.last ?? line
    }
    
    private func iconForLevel(_ level: String) -> String {
        switch level {
        case "ERROR": return "xmark.circle.fill"
        case "SUCCESS": return "checkmark.circle.fill"
        case "RECOVERY": return "bandage.fill"
        case "WARN": return "exclamationmark.triangle.fill"
        default: return "info.circle"
        }
    }
    
    private func colorForLevel(_ level: String) -> Color {
        switch level {
        case "ERROR": return .red
        case "SUCCESS": return .green
        case "RECOVERY": return .orange
        case "WARN": return .yellow
        default: return .primary
        }
    }
}

// MARK: - Hot Button

struct HotButton: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void
    let disabled: Bool
    var isRisky: Bool = false
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                Image(systemName: icon)
                Text(title)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                if isRisky {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.caption2)
                        .foregroundColor(.yellow)
                }
            }
        }
        .buttonStyle(.borderedProminent)
        .tint(color)
        .controlSize(.regular)
        .frame(maxWidth: .infinity)
        .disabled(disabled)
    }
}

// MARK: - Recovered Log View

struct RecoveredLogView: View {
    let content: String
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationStack {
            ScrollView {
                Text(content)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .navigationTitle("Recovered Log")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        UIPasteboard.general.string = content
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                }
            }
        }
    }
}

// MARK: - Probes List View

struct ProbesListView: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationStack {
            List {
                Section("KASLR") {
                    Button("AKS (CVE-2026-65343)") { 
                        dismiss()
                        viewModel.testAKS() 
                    }
                }
                
                Section("PAC") {
                    Button("PAC Bypass (CVE-2026-65330)") { 
                        dismiss()
                        viewModel.testPACBypass() 
                    }
                }
                
                Section("OOB") {
                    Button("OOB Write (CVE-2026-65349)") { 
                        dismiss()
                        viewModel.testOOBWrite() 
                    }
                }
                
                Section("Persistence") {
                    Button("APFS (CVE-2026-84523)") { 
                        dismiss()
                        viewModel.testAPFS() 
                    }
                }
            }
            .navigationTitle("All Probes")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

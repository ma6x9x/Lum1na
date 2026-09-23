//
//  ContentView.swift
//  Minimal - uses your existing ViewModel
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()
    @State private var showingStageTester = false
    
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            
            VStack(spacing: 20) {
                // Simple header
                Text("Lum1na")
                    .font(.largeTitle)
                    .foregroundColor(.white)
                    .padding(.top, 40)
                
                // Status text
                Text(viewModel.exploitState.description)
                    .font(.headline)
                    .foregroundColor(statusColor)
                    .padding()
                
                // Console output
                ScrollView {
                    Text(viewModel.consoleText)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.green)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(height: 200)
                .background(Color.black.opacity(0.5))
                .cornerRadius(8)
                .padding(.horizontal)
                
                // Stage buttons
                HStack(spacing: 10) {
                    Button("KERNEL") { 
                        Task { await viewModel.executeStage("KERNEL") }
                    }
                    .buttonStyle(StageButtonStyle(color: .blue))
                    
                    Button("SANDBOX") { 
                        Task { await viewModel.executeStage("SANDBOX") }
                    }
                    .buttonStyle(StageButtonStyle(color: .orange))
                    
                    Button("DAEMON") { 
                        Task { await viewModel.executeStage("DAEMON") }
                    }
                    .buttonStyle(StageButtonStyle(color: .purple))
                    
                    Button("PATCH") { 
                        Task { await viewModel.executeStage("PATCHSET") }
                    }
                    .buttonStyle(StageButtonStyle(color: .red))
                }
                .padding(.horizontal)
                
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
                .padding(.horizontal)
                .disabled(viewModel.isRunning)
                
                Spacer()
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

// Simple button style
struct StageButtonStyle: ButtonStyle {
    let color: Color
    
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.caption)
            .foregroundColor(.white)
            .frame(width: 70, height: 44)
            .background(color.opacity(0.3))
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(color, lineWidth: 1)
            )
            .scaleEffect(configuration.isPressed ? 0.95 : 1)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

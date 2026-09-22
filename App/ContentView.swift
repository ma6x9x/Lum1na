//
//  ContentView.swift
//  Lum1na
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()
    @State private var showingStageTester = false
    
    var body: some View {
        ZStack {
            Color(hex: "07060F").ignoresSafeArea()
            
            VStack(spacing: 0) {
                // MARK: - Header
                HeaderView()
                    .padding(.top, 12)
                
                // MARK: - Device Info
                DeviceInfoCompact(viewModel: viewModel)
                    .padding(.horizontal, 20)
                    .padding(.top, 8)
                
                // MARK: - Star Beacon
                StarBeaconSection(viewModel: viewModel)
                    .padding(.top, 10)
                
                Text("The guiding light for Jailbreaks")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .padding(.top, 8)
                
                // MARK: - Console
                ConsoleCard(viewModel: viewModel)
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
                
                // MARK: - Primitive Test Buttons
                HStack(spacing: 12) {
                    Button(action: { viewModel.testAKS() }) {
                        Label("Test AKS", systemImage: "memorychip")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(Capsule().fill(Color.blue))
                    }
                    .disabled(viewModel.isRunning)
                    
                    Button(action: { viewModel.testAPFS() }) {
                        Label("Test APFS", systemImage: "externaldrive")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(Capsule().fill(Color.green))
                    }
                    .disabled(viewModel.isRunning)
                }
                .padding(.horizontal, 16)
                .padding(.top, 10)
                
                // MARK: - Action Buttons
                HStack(spacing: 12) {
                    Button(action: { showingStageTester = true }) {
                        Label("Test Stages", systemImage: "slider.horizontal.3")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(.primary)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(Capsule().fill(.ultraThinMaterial))
                    }
                    
                    Button(action: { viewModel.startJailbreak() }) {
                        Text("Jailbreak")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(
                                Capsule().fill(
                                    LinearGradient(
                                        colors: [Color(hex: "FF6B9D"), Color(hex: "9B59B6")],
                                        startPoint: .leading,
                                        endPoint: .trailing
                                    )
                                )
                            )
                    }
                    .disabled(viewModel.isRunning)
                }
                .padding(.horizontal, 16)
                .padding(.top, 10)
                .padding(.bottom, 16)
            }
        }
        .sheet(isPresented: $showingStageTester) {
            StageTesterView(viewModel: viewModel)
        }
    }
}

// MARK: - Header View
struct HeaderView: View {
    var body: some View {
        VStack(spacing: 2) {
            Text("Lum1na")
                .font(.system(size: 32, weight: .bold, design: .rounded))
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color(hex: "FF6B9D"), Color(hex: "4ECDC4")],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
            
            Text("v0.1 • private beta")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(.gray)
        }
    }
}

// MARK: - Device Info
struct DeviceInfoCompact: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "iphone")
                .font(.system(size: 14))
                .foregroundStyle(Color(hex: "4ECDC4"))
            
            VStack(alignment: .leading, spacing: 1) {
                Text(viewModel.deviceInfo?.machine ?? "Detecting...")
                    .font(.system(size: 13, weight: .semibold))
                Text("iOS \(viewModel.deviceInfo?.version ?? "?")")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            HStack(spacing: 4) {
                Circle()
                    .fill(viewModel.statusColor)
                    .frame(width: 6, height: 6)
                Text(viewModel.statusText)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(viewModel.statusColor)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            Capsule()
                .fill(.ultraThinMaterial)
                .overlay(Capsule().stroke(Color.white.opacity(0.1), lineWidth: 1))
        )
        .frame(maxWidth: 260, alignment: .center)
    }
}

// MARK: - Star Beacon Section
struct StarBeaconSection: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        ZStack {
            Circle()
                .stroke(
                    LinearGradient(
                        colors: [Color(hex: "FF6B9D"), Color(hex: "4ECDC4")],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 2
                )
                .frame(width: 130, height: 130)
            
            Circle()
                .fill(.ultraThinMaterial)
                .frame(width: 120, height: 120)
            
            StarBeaconView(stage: viewModel.currentStage)
                .frame(width: 80, height: 80)
        }
        .frame(height: 140)
    }
}

// MARK: - Console Card
struct ConsoleCard: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label("console", systemImage: "terminal")
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
                
                Spacer()
                
                Button(action: { UIPasteboard.general.string = viewModel.consoleText }) {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                
                Button(action: { viewModel.clearConsole() }) {
                    Image(systemName: "trash")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .padding(.leading, 8)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            
            Divider().background(Color.white.opacity(0.1))
            
            ScrollView(.vertical, showsIndicators: true) {
                Text(viewModel.consoleText)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.cyan)
                    .lineSpacing(2)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .frame(height: 140)
        }
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color(hex: "FF6B9D").opacity(0.3), lineWidth: 1)
                )
        )
    }
}

// MARK: - Stage Tester View
struct StageTesterView: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @Environment(\.dismiss) var dismiss
    
    let stages = [
        ("KASLR Bypass", "memorychip", "Test AKS KASLR leak"),
        ("Heap Corruption", "cpu", "Test APFS nstream"),
    ]
    
    var body: some View {
        NavigationView {
            List {
                Section(header: Text("Primitive Testing")) {
                    ForEach(stages, id: \.0) { stage in
                        Button(action: {
                            if stage.0 == "KASLR Bypass" {
                                viewModel.testAKS()
                            } else if stage.0 == "Heap Corruption" {
                                viewModel.testAPFS()
                            }
                            dismiss()
                        }) {
                            HStack(spacing: 12) {
                                Image(systemName: stage.1)
                                    .font(.system(size: 20))
                                    .foregroundStyle(Color(hex: "FF6B9D"))
                                    .frame(width: 40, height: 40)
                                    .background(Color(hex: "FF6B9D").opacity(0.1))
                                    .cornerRadius(10)
                                
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(stage.0)
                                        .font(.system(size: 16, weight: .semibold))
                                    Text(stage.2)
                                        .font(.system(size: 12))
                                        .foregroundStyle(.secondary)
                                }
                                
                                Spacer()
                                
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 14))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                
                Section {
                    Button("Reset State") { viewModel.reset() }
                        .foregroundStyle(.red)
                }
            }
            .navigationTitle("Stage Tester")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

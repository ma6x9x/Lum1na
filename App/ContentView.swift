import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = Lum1naViewModel()
    @State private var showingStageTester = false
    
    var body: some View {
        ZStack {
            Color(hex: "07060F").ignoresSafeArea()
            
            ScrollView(.vertical, showsIndicators: false) {
                VStack(spacing: 0) {
                    // Device info - top left corner, smaller
                    DeviceInfoCompact()
                        .padding(.horizontal, 20)
                        .padding(.top, 12)
                    
                    // LUM1NA logo - brought up
                    HeaderView()
                        .padding(.top, 20)
                    
                    // Star beacon
                    StarBeaconSection(viewModel: viewModel)
                        .padding(.top, 16)
                    
                    // Tagline
                    Text("The guiding light for Jailbreaks")
                        .font(.system(size: 14))
                        .foregroundStyle(.secondary)
                        .padding(.top, 12)
                    
                    // Console - LARGER (250pt height)
                    ConsoleCard(viewModel: viewModel)
                        .padding(.horizontal, 16)
                        .padding(.top, 20)
                    
                    // Stage buttons
                    StageButtonsRow(viewModel: viewModel)
                        .padding(.horizontal, 12)
                        .padding(.top, 16)
                    
                    // Action buttons - REPLACED "Hide stages" with "Test Stages"
                    HStack(spacing: 12) {
                        Button(action: { showingStageTester = true }) {
                            Label("Test Stages", systemImage: "slider.horizontal.3")
                                .font(.system(size: 15, weight: .semibold))
                                .foregroundStyle(.primary)
                                .frame(maxWidth: .infinity, height: 50)
                                .background(Capsule().fill(.ultraThinMaterial))
                        }
                        
                        Button(action: { viewModel.startJailbreak() }) {
                            Text("Jailbreak")
                                .font(.system(size: 15, weight: .bold))
                                .foregroundStyle(.white)
                                .frame(maxWidth: .infinity, height: 50)
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
                    .padding(.top, 16)
                    .padding(.bottom, 30)
                }
            }
        }
        .sheet(isPresented: $showingStageTester) {
            StageTesterView(viewModel: viewModel)
        }
    }
}

// MARK: - Compact Device Info (Top Left)
struct DeviceInfoCompact: View {
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "iphone")
                .font(.system(size: 12))
                .foregroundStyle(Color(hex: "4ECDC4"))
            
            VStack(alignment: .leading, spacing: 1) {
                Text("iPhone 12")
                    .font(.system(size: 12, weight: .semibold))
                Text("iOS 26.5")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            HStack(spacing: 4) {
                Circle()
                    .fill(Color(hex: "4ECDC4"))
                    .frame(width: 6, height: 6)
                Text("A14")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Color(hex: "4ECDC4"))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            Capsule()
                .fill(.ultraThinMaterial)
                .overlay(Capsule().stroke(Color.white.opacity(0.1), lineWidth: 1))
        )
        .frame(maxWidth: 180, alignment: .leading)
    }
}

// MARK: - Larger Console (250pt height)
struct ConsoleCard: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label("console", systemImage: "terminal")
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
                
                Spacer()
                
                Button(action: {
                    UIPasteboard.general.string = viewModel.consoleText
                }) {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                }
                
                Button(action: { viewModel.clearConsole() }) {
                    Image(systemName: "trash")
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                        .padding(.leading, 8)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            
            Divider().background(Color.white.opacity(0.1))
            
            ScrollView(.vertical, showsIndicators: true) {
                Text(viewModel.consoleText)
                    .font(.system(size: 13, design: .monospaced)) // Slightly larger
                    .foregroundStyle(.cyan)
                    .lineSpacing(3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .frame(height: 250) // INCREASED from 180
        }
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color(hex: "FF6B9D").opacity(0.3), lineWidth: 1)
                )
        )
    }
}

// MARK: - Stage Tester Sheet (Replaces "Hide stages")
struct StageTesterView: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @Environment(\.dismiss) var dismiss
    
    let stages = [
        ("KASLR Bypass", "memorychip", "Test KASLR leak primitive"),
        ("Heap Corruption", "cpu", "Test heap grooming/UAF"),
        ("ANE Exploit", "brain", "Test ANE 43748 write class"),
        ("PPL Bypass", "lock.shield", "Test PPL defeat"),
        ("Persistence", "arrow.clockwise", "Test tempRoot installation")
    ]
    
    var body: some View {
        NavigationView {
            List {
                Section(header: Text("Individual Stage Testing")) {
                    ForEach(stages, id: \.0) { stage in
                        StageTestRow(
                            title: stage.0,
                            icon: stage.1,
                            description: stage.2,
                            action: {
                                viewModel.testIndividualStage(stage.0)
                                dismiss()
                            }
                        )
                    }
                }
                
                Section(header: Text("Diagnostics")) {
                    Button("Clear Console") {
                        viewModel.clearConsole()
                    }
                    .foregroundStyle(.red)
                    
                    Button("Reset State") {
                        viewModel.reset()
                    }
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

struct StageTestRow: View {
    let title: String
    let icon: String
    let description: String
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 20))
                    .foregroundStyle(Color(hex: "FF6B9D"))
                    .frame(width: 40, height: 40)
                    .background(Color(hex: "FF6B9D").opacity(0.1))
                    .cornerRadius(10)
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 16, weight: .semibold))
                    Text(description)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                
                Spacer()
                
                Image(systemName: "chevron.right")
                    .font(.system(size: 14))
                    .foregroundStyle(.secondary)
            }
        }
    }
}

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
                    DeviceInfoCompact(viewModel: viewModel)
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
                    
                    // Console card - LARGER
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

// MARK: - Supporting Views

struct HeaderView: View {
    var body: some View {
        VStack(spacing: 4) {
            Text("Lum1na")
                .font(.system(size: 42, weight: .bold, design: .rounded))
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color(hex: "FF6B9D"), Color(hex: "4ECDC4")],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
            
            Text("v0.1 • private beta")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.gray)
        }
    }
}

struct DeviceInfoCompact: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "iphone")
                .font(.system(size: 12))
                .foregroundStyle(Color(hex: "4ECDC4"))
            
            VStack(alignment: .leading, spacing: 1) {
                Text(viewModel.deviceInfo?.machine ?? "Unknown")
                    .font(.system(size: 12, weight: .semibold))
                Text("iOS \(viewModel.deviceInfo?.version ?? "?")")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            HStack(spacing: 4) {
                Circle()
                    .fill(viewModel.statusColor)
                    .frame(width: 6, height: 6)
                Text(viewModel.exploitState == .idle ? "Ready" : viewModel.exploitState.description)
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
        .frame(maxWidth: 200, alignment: .leading)
    }
}

struct StarBeaconSection: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @State private var isPulsing = false
    
    var body: some View {
        ZStack {
            Circle()
                .fill(.ultraThinMaterial)
                .frame(width: 180, height: 180)
                .overlay(
                    Circle()
                        .stroke(
                            LinearGradient(
                                colors: [Color(hex: "FF6B9D"), Color(hex: "4ECDC4")],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            ),
                            lineWidth: 2
                        )
                )
            
            Image(systemName: "star.circle.fill")
                .font(.system(size: 60))
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color(hex: "FF6B9D"), Color(hex: "9B59B6"), Color(hex: "4ECDC4")],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .shadow(color: Color(hex: "9B59B6").opacity(0.6), radius: 15)
                .scaleEffect(isPulsing ? 1.05 : 1.0)
                .animation(.easeInOut(duration: 2).repeatForever(autoreverses: true), value: isPulsing)
        }
        .frame(height: 200)
        .onAppear { isPulsing = true }
    }
}

struct ConsoleCard: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label("console", systemImage: "terminal")
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
                
                Spacer()
                
                Button(action: { UIPasteboard.general.string = viewModel.consoleText }) {
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
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(.cyan)
                    .lineSpacing(3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .frame(height: 250) // LARGER console
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

struct StageButtonsRow: View {
    @ObservedObject var viewModel: Lum1naViewModel
    
    let stages = [
        ("KASLR", "memorychip"),
        ("Heap", "cpu"),
        ("ANE", "brain"),
        ("PPL", "lock.shield"),
        ("Persist", "arrow.clockwise")
    ]
    
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(stages, id: \.0) { stage in
                    VStack(spacing: 4) {
                        Image(systemName: stage.1)
                            .font(.system(size: 16))
                        Text(stage.0)
                            .font(.system(size: 11, weight: .medium))
                    }
                    .foregroundStyle(.secondary)
                    .frame(width: 60, height: 50)
                    .background(
                        Capsule()
                            .fill(.ultraThinMaterial)
                            .overlay(Capsule().stroke(Color.white.opacity(0.1), lineWidth: 1))
                    )
                }
            }
            .padding(.horizontal, 4)
        }
    }
}

struct StageTesterView: View {
    @ObservedObject var viewModel: Lum1naViewModel
    @Environment(\.dismiss) var dismiss
    
    let stages = [
        ("KASLR Bypass", "memorychip", "Test KASLR leak"),
        ("Heap Corruption", "cpu", "Test heap grooming"),
        ("ANE Exploit", "brain", "Test ANE 43748"),
        ("P005 JIT", "bolt", "Test P005 disclose"),
        ("PPL Bypass", "lock.shield", "Test PPL defeat"),
        ("Persistence", "arrow.clockwise", "Test tempRoot")
    ]
    
    var body: some View {
        NavigationView {
            List {
                Section(header: Text("Individual Stage Testing")) {
                    ForEach(stages, id: \.0) { stage in
                        Button(action: {
                            viewModel.testIndividualStage(stage.0)
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

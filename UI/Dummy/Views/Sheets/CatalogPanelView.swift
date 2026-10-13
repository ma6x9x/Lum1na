import SwiftUI

/// Exploit catalog as a board panel (same centered card as settings). Tapping
/// an entry closes the panel and runs it.
struct CatalogPanelView: View {
    @ObservedObject var viewModel: ExploitManager
    var onClose: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            sectionHeader("EXPLOIT CATALOG – TAP TO RUN INDIVIDUALLY")
            VStack(spacing: 10) {
                ForEach(ExploitManager.catalog) { entry in
                    Button {
                        onClose()
                        Task {
                            await viewModel.executeExploit(entry)
                        }
                    } label: {
                        catalogRow(entry)
                    }
                    .buttonStyle(.plain)
                    .disabled(viewModel.isRunning)
                }
            }
            .padding(14)
            .glassSurface(RoundedRectangle(cornerRadius: 28, style: .continuous))

            Text("Every invoke writes a durable TAP marker before running. After a crash, the recovery transcript shows exactly which entry was last attempted.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
                .padding(.horizontal, 8)
        }
        .padding(.horizontal, 4)
    }

    private func sectionHeader(_ text: String) -> some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .tracking(1.2)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 6)
    }

    private func catalogRow(_ entry: ExploitCatalogEntry) -> some View {
        HStack {
            Image(systemName: entry.stage.icon)
                .foregroundColor(entry.stage.color)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 2) {
                Text(entry.name)
                    .font(.subheadline.weight(.semibold))
                    .foregroundColor(.primary)
                Text(entry.description)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            if viewModel.isRunning && viewModel.selectedStage == entry.stage {
                ProgressView()
                    .scaleEffect(0.7)
            } else {
                Image(systemName: "play.circle")
                    .foregroundColor(entry.stage.color.opacity(0.7))
            }
        }
        .padding(.horizontal, 12)
        .frame(minHeight: 52)
        .background(.white.opacity(0.08), in: .rect(cornerRadius: 14, style: .continuous))
    }
}

#Preview("Catalog panel") {
    BoardPanelView(title: "All Exploits") {
        CatalogPanelView(viewModel: ExploitManager.shared, onClose: {})
    }
    .frame(maxWidth: 560)
    .padding(18)
    .background(Color(red: 0.02, green: 0.024, blue: 0.06))
    .preferredColorScheme(.dark)
}

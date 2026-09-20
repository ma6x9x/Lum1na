import SwiftUI

/// Presentation-only console that mirrors `ExploitManager` log lines.
/// Does not own or alter exploit / race logic.
struct MatrixConsoleView: View {
    @ObservedObject private var manager = ExploitManager.shared

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 3) {
                    ForEach(manager.lines) { line in
                        Text(line.text)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(line.color)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .id(line.id)
                    }
                }
                .padding(10)
            }
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(Color.black.opacity(0.72))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(
                        LinearGradient(
                            colors: [
                                Color.white.opacity(0.28),
                                Color.purple.opacity(0.35),
                                Color.white.opacity(0.08)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 1
                    )
            )
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .onChange(of: manager.lines.count) { _ in
                guard let last = manager.lines.last else { return }
                withAnimation(.easeOut(duration: 0.12)) {
                    proxy.scrollTo(last.id, anchor: .bottom)
                }
            }
        }
        .accessibilityLabel("Session console")
    }
}

//
//  ConsoleTabView.swift
//  Lum1na — CRT-first live ExploitManager.lines.
//

import SwiftUI

struct ConsoleTabView: View {
    @Environment(LuminaAppStore.self) private var store
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var stickToBottom = true

    private var filtered: [ConsoleLine] {
        store.lines.filter { line in
            if !store.consoleQuery.isEmpty {
                let q = store.consoleQuery.lowercased()
                if !line.message.lowercased().contains(q) && !line.formatted.lowercased().contains(q) {
                    return false
                }
            }
            switch store.consoleLevelFilter {
            case .all: return true
            case .info: return line.level == .info || line.level == .success
            case .warn: return line.level == .warning
            case .error: return line.level == .error || line.level == .warning
            }
        }
    }

    var body: some View {
        @Bindable var store = store
        NavigationStack {
            ZStack {
                LuminaV2Theme.canvas.ignoresSafeArea()
                VStack(spacing: 12) {
                    HStack(spacing: 8) {
                        Text("LUM1NA")
                            .font(.caption.weight(.bold).monospaced())
                            .foregroundStyle(LuminaV2Theme.crtGreen)
                        Circle().fill(store.isRunning || store.settings.liveStream ? LuminaV2Theme.crtGreen : LuminaV2Theme.pending)
                            .frame(width: 7, height: 7)
                        Text(store.consolePaused ? "PAUSED" : "LIVE")
                            .font(.caption.weight(.semibold).monospaced())
                            .foregroundStyle(LuminaV2Theme.crtGreen.opacity(0.85))
                        Spacer()
                    }
                    .padding(.horizontal, 16)

                    HStack(spacing: 8) {
                        Image(systemName: "magnifyingglass")
                            .foregroundStyle(LuminaV2Theme.crtGreen.opacity(0.7))
                        TextField("Search process, subsystem, message", text: $store.consoleQuery)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .foregroundStyle(LuminaV2Theme.crtGreen)
                    }
                    .padding(10)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .strokeBorder(LuminaV2Theme.crtGreen.opacity(0.35), lineWidth: 1)
                    )
                    .padding(.horizontal, 16)

                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(LuminaAppStore.ConsoleLevelFilter.allCases) { filter in
                                Button {
                                    store.consoleLevelFilter = filter
                                } label: {
                                    Text(filter.rawValue)
                                        .font(.caption.weight(.semibold))
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 6)
                                        .background(
                                            Capsule().fill(store.consoleLevelFilter == filter
                                                           ? LuminaV2Theme.crtGreen.opacity(0.2)
                                                           : Color.white.opacity(0.05))
                                        )
                                        .overlay(
                                            Capsule().strokeBorder(
                                                store.consoleLevelFilter == filter
                                                ? LuminaV2Theme.crtGreen.opacity(0.7)
                                                : Color.white.opacity(0.1), lineWidth: 1)
                                        )
                                        .foregroundStyle(LuminaV2Theme.crtGreen)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                        .padding(.horizontal, 16)
                    }

                    ZStack(alignment: .bottomTrailing) {
                        ScrollViewReader { proxy in
                            ScrollView {
                                LazyVStack(alignment: .leading, spacing: 6) {
                                    ForEach(filtered) { line in
                                        Text(line.formatted)
                                            .font(.system(.caption, design: .monospaced))
                                            .foregroundStyle(crtColor(line.level))
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                            .id(line.id)
                                        Rectangle()
                                            .fill(LuminaV2Theme.crtGreen.opacity(0.08))
                                            .frame(height: 1)
                                    }
                                    Color.clear.frame(height: 8).id("console-bottom")
                                }
                                .padding(16)
                            }
                            .background(
                                RoundedRectangle(cornerRadius: 16, style: .continuous)
                                    .fill(Color.black.opacity(0.55))
                                    .overlay {
                                        // subtle scanlines
                                        LinearGradient(
                                            colors: [Color.clear, LuminaV2Theme.crtGreen.opacity(0.03), Color.clear],
                                            startPoint: .top,
                                            endPoint: .bottom
                                        )
                                        .allowsHitTesting(false)
                                    }
                            )
                            .padding(.horizontal, 12)
                            .onChange(of: store.lines.count) { _, _ in
                                guard stickToBottom, !store.consolePaused, store.settings.liveStream else { return }
                                withAnimation(LuminaV2Theme.spring(reduceMotion: reduceMotion)) {
                                    proxy.scrollTo("console-bottom", anchor: .bottom)
                                }
                            }

                            if !stickToBottom {
                                Button {
                                    stickToBottom = true
                                    proxy.scrollTo("console-bottom", anchor: .bottom)
                                } label: {
                                    Label("Jump to latest", systemImage: "arrow.down")
                                        .font(.caption.weight(.semibold))
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 8)
                                }
                                .buttonStyle(.borderedProminent)
                                .tint(LuminaV2Theme.accent)
                                .padding(16)
                            }
                        }
                        .simultaneousGesture(
                            DragGesture().onChanged { _ in stickToBottom = false }
                        )
                    }
                }
                .padding(.top, 8)
                .padding(.bottom, 8)
            }
            .navigationTitle("Console")
            .toolbar {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button {
                        store.consolePaused.toggle()
                        if !store.consolePaused { store.syncLinesFromManager() }
                    } label: {
                        Image(systemName: store.consolePaused ? "play.fill" : "pause.fill")
                            .frame(width: 44, height: 44)
                    }
                    .accessibilityLabel(store.consolePaused ? "Resume" : "Pause")

                    Button {
                        store.copyToPasteboard(store.exportConsole())
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .frame(width: 44, height: 44)
                    }
                    .accessibilityLabel("Copy console")

                    ShareLink(item: store.exportConsole()) {
                        Image(systemName: "square.and.arrow.up")
                            .frame(width: 44, height: 44)
                    }
                    .accessibilityLabel("Share console")

                    Button(role: .destructive) {
                        store.clearConsole()
                    } label: {
                        Image(systemName: "trash")
                            .frame(width: 44, height: 44)
                    }
                    .accessibilityLabel("Clear console")
                }
            }
        }
    }

    private func crtColor(_ level: ConsoleLine.LogLevel) -> Color {
        switch level {
        case .info: return LuminaV2Theme.crtGreen.opacity(0.85)
        case .success: return LuminaV2Theme.crtGreen
        case .warning: return LuminaV2Theme.amber
        case .error: return LuminaV2Theme.danger
        }
    }
}

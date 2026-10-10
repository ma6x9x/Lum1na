//
//  HourLogGallery.swift
//  Lum1na
//
//  Logs written in the last hour. Opened from Settings, not the home screen.
//

import SwiftUI

struct HourLogGallery: View {
    @Environment(\.dismiss) private var dismiss
    @State private var items: [PersistentLogStore.HourLog] = []
    @State private var picked: PersistentLogStore.HourLog?

    var body: some View {
        NavigationStack {
            Group {
                if items.isEmpty {
                    Text("No log files touched in the last hour.")
                        .font(.system(.body, design: .rounded))
                        .foregroundStyle(.secondary)
                        .padding()
                } else {
                    List(items) { item in
                        Button {
                            picked = item
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.name)
                                    .font(.system(.subheadline, design: .monospaced))
                                    .foregroundStyle(.primary)
                                Text(item.modified.formatted(date: .omitted, time: .standard))
                                    .font(.system(.caption, design: .rounded))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Last hour")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Done") { dismiss() }
                }
            }
            .navigationDestination(item: $picked) { item in
                ScrollView {
                    Text(PersistentLogStore.shared.readLog(at: item.url))
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        .textSelection(.enabled)
                }
                .navigationTitle(item.name)
                .navigationBarTitleDisplayMode(.inline)
            }
            .onAppear {
                items = PersistentLogStore.shared.logsTouched(within: 60 * 60)
            }
        }
    }
}

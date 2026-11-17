//
//  DeviceHeaderBar.swift
//  Lum1na
//

import SwiftUI

struct DeviceHeaderBar: View {
    @Environment(LuminaAppStore.self) private var store

    var body: some View {
        HStack(spacing: 8) {
            Text("\(store.machine) • \(store.boardConfig)")
                .font(.caption.weight(.semibold).monospaced())
                .foregroundStyle(LuminaV2Theme.cyan)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(Capsule().fill(LuminaV2Theme.cyan.opacity(0.12)))
                .lineLimit(1)
                .minimumScaleFactor(0.7)

            Text("iOS \(store.iosVersion)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)

            Spacer(minLength: 4)

            HStack(spacing: 6) {
                Circle()
                    .fill(store.readyColor)
                    .frame(width: 8, height: 8)
                    .accessibilityHidden(true)
                Text(store.readyLabel)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(store.readyColor)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Status \(store.readyLabel)")
        }
        .padding(.horizontal, 4)
    }
}

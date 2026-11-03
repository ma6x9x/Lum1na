//
//  KernelLabPane.swift — IPA-safe KernelLab surface.
//  Host Unicorn (klconsole.py :8737) stays on the Mac. The phone exports
//  board JSON, applies the flat-VA law, and fires P118 boot-learner.
//

import SwiftUI
import UIKit

struct KernelLabPane: View {
    @State private var vaIn = "0xfffffe0008790cec"
    @State private var vaOut = ""
    @State private var boardText = ""
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionLabel(text: "KernelLab")
            Text("Host Unicorn tables/diff/emu43748 live on the Mac (klconsole.py :8737). This pane is the device half: board export, flat-VA law, P118 boot-learner. No kernelcache is bundled.")
                .font(T.body)
                .foregroundColor(.white.opacity(0.62))
                .fixedSize(horizontal: false, vertical: true)

            KeyValueRow(key: "kreadSignal", value: P007Board.shared().kreadSignal)
            KeyValueRow(key: "flat-VA", value: "fileoff = (va & 0xFFFFFFF) − 0x7004000")

            HStack(spacing: 8) {
                TextField("VA", text: $vaIn)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(T.monoSm)
                    .foregroundColor(.white)
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 8).fill(T.panelHi))
                Button("fileoff") {
                    vaOut = LuminaMindToolsCall.va(vaIn)
                }
                .font(T.tiny)
                .foregroundColor(T.ember)
            }
            if !vaOut.isEmpty {
                Text(vaOut)
                    .font(T.monoSm)
                    .foregroundColor(T.good)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack(spacing: 8) {
                RunButton(title: "Export board JSON", systemImage: "square.and.arrow.up", tint: T.info) {
                    boardText = loadBoard()
                    UIPasteboard.general.string = boardText
                    copied = true
                }
                RunButton(title: "P118 boot-learn", systemImage: "brain", tint: T.ember) {
                    boardText = LuminaTAP.execute("p118")
                }
            }

            if copied {
                Text("board JSON copied")
                    .font(T.tiny)
                    .foregroundColor(T.good)
            }
            if !boardText.isEmpty {
                ScrollView {
                    Text(boardText)
                        .font(T.monoSm)
                        .foregroundColor(.white.opacity(0.7))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 220)
            }
        }
    }

    private func loadBoard() -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let url = docs.appendingPathComponent("p007_board.json")
        return (try? String(contentsOf: url, encoding: .utf8)) ?? "(p007_board.json missing — tap Ident first)"
    }
}

/// Tiny VA helper so KernelLabPane does not depend on Mind tool internals staying public.
enum LuminaMindToolsCall {
    static func va(_ raw: String) -> String {
        let hex = raw.lowercased().replacingOccurrences(of: "0x", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let v = UInt64(hex, radix: 16) else { return "need hex VA" }
        let fileoff = Int64(v & 0xFFFFFFF) - 0x7004000
        return String(format: "fileoff=0x%llx (%lld)", fileoff, fileoff)
    }
}

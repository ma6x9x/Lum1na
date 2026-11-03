//
//  KernelLabPane.swift — IPA-safe KernelLab 0.3.2 surface.
//  Host Unicorn (klconsole.py :8737, kernellab.py, oracle_bridge.py) stays
//  on the Mac / post-jb .deb. This pane is the device half: board export,
//  flat-VA law, P118 boot-learner, stage ladder labels, lab_bandit.json
//  export for `kernellab sim ident --feed` / `oracle_bridge show`.
//
//  Not shipped here: KernelLab.app Mach-O, uicache, Unicorn, kernelcaches,
//  /var/jb/var/kernellab/probes. APPLE-SUBMIT stays closed.
//

import SwiftUI
import UIKit

struct KernelLabPane: View {
    @State private var vaIn = "0xfffffe0008790cec"
    @State private var vaOut = ""
    @State private var boardText = ""
    @State private var copied = false
    @State private var banner = LuminaLearn.stageLadder()

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionLabel(text: "KernelLab 0.3.2")
            Text("Host Unicorn tables/diff/emu43748 live on the Mac (klconsole.py :8737). This pane is the device half: board export, flat-VA law, P118, LabBandit lattice, oracle_bridge dump. No kernelcache is bundled. A stage label is not a device receipt.")
                .font(T.body)
                .foregroundColor(.white.opacity(0.62))
                .fixedSize(horizontal: false, vertical: true)

            KeyValueRow(key: "kreadSignal", value: P007Board.shared().kreadSignal)
            KeyValueRow(key: "flat-VA", value: "fileoff = (va & 0xFFFFFFF) − 0x7004000")
            KeyValueRow(key: "lattice", value: LuminaLearn.latticeLine)
            KeyValueRow(key: "evidence", value: LuminaLearn.evidenceLaw)
            KeyValueRow(key: "gate", value: LuminaLearn.appleSubmit, tint: T.warn)

            HStack(spacing: 6) {
                ForEach(LuminaStage.allCases, id: \.rawValue) { st in
                    Text(st.rawValue)
                        .font(T.tiny)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 4)
                        .background(RoundedRectangle(cornerRadius: 6).fill(stageColor(st).opacity(0.22)))
                        .foregroundColor(stageColor(st))
                }
            }

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

            VStack(spacing: 8) {
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
                HStack(spacing: 8) {
                    RunButton(title: "Bandit plan", systemImage: "list.number", tint: T.good) {
                        boardText = LuminaLearn.status()
                    }
                    RunButton(title: "Oracle export", systemImage: "arrow.down.doc", tint: T.info) {
                        boardText = LuminaLearn.exportOracle()
                        UIPasteboard.general.string = boardText
                        copied = true
                    }
                }
                HStack(spacing: 8) {
                    RunButton(title: "NOTES/004 copy block", systemImage: "doc.on.doc", tint: T.warn) {
                        boardText = LuminaLearn.copyBlock()
                        UIPasteboard.general.string = boardText
                        copied = true
                    }
                    RunButton(title: "Apply survivor knobs", systemImage: "arrow.triangle.2.circlepath", tint: T.ember) {
                        boardText = LuminaLearn.applySurvivorKnobs()
                    }
                }
            }

            Text(banner)
                .font(T.tiny)
                .foregroundColor(.white.opacity(0.45))
                .fixedSize(horizontal: false, vertical: true)

            if copied {
                Text("copied to pasteboard")
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
                .frame(maxHeight: 260)
            }
        }
    }

    private func stageColor(_ st: LuminaStage) -> Color {
        switch st {
        case .sandbox, .leak, .krw: return T.good
        case .race, .write: return T.warn
        case .sptm: return T.ember
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

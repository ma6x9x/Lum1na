import SwiftUI
import UIKit

// MARK: - Chain

struct ChainStage: Identifiable {
    let id: String
    let index: Int
    let title: String
    let goal: String
    let moduleIDs: [String]
    let unlock: String
}

enum ChainPlan {
    static let stages: [ChainStage] = [
        ChainStage(id: "sL0", index: 0,
                   title: "Lum1na 17 KRW",
                   goal: "T8150 formula: P139 harvest + P114 leak + P149 v7 encode-first conversion. PIPE-HIT is a write receipt. hasKread only after kread32(kbase)==0xfeedfacf.",
                   moduleIDs: ["ident", "p139", "p114", "p149", "kreadtest"],
                   unlock: "One TAP per force-quit. Reboot after P149. Do not stack with P044."),

        ChainStage(id: "sL1", index: 1,
                   title: "Lum1na hunt occupancy",
                   goal: "A14 23F77 occupancy WRITE (P044 / CONV). Occupancy HIT is not conversion and not hasKread. PATHS is the per-path scorecard.",
                   moduleIDs: ["ident", "p044", "conv", "pathtest", "kreadtest"],
                   unlock: "HOLE_MODE stays 0. Do not remaining-fire 254 unbounded fill."),

        ChainStage(id: "sL2", index: 2,
                   title: "Lum1na KernelLab + Mind + Learn",
                   goal: "P118 boot-learner + LabBandit lattice (sandbox→leak→race→write→krw→sptm). Mind tools: bandit_plan, promote_status, oracle_export. Host KernelLab 0.3.2 oracle_bridge mirrors Documents/lab_bandit.json.",
                   moduleIDs: ["board", "p118", "p100", "intel"],
                   unlock: "Host Unicorn stays on the Mac. IPA does not embed kernelcaches. A stage label is not hasKread."),

        ChainStage(id: "sF1", index: 3,
                   title: "FGROOM · Family-B race→write",
                   goal: "The Family-B conversion (12 and 17 both hold a won window). Outcome (c) proved the reclaim re-hands the victim's own slot (pop[0]==victim sid); outcome (b) proved the stale consumer DEREFERENCES the freed slot in-window. p110_groom.txt='cafe0fedcafe0fed,48' makes the reclaim racer fire kdata-0x1000 kmsgs in-window with the chosen qword at +0x30 — the stale consumer's +0x30 read then aims at OUR bytes. Receipt class = OUTCOME (c) anomalies on groomed rounds (faults stop being the only signal).",
                   moduleIDs: ["p110", "kreadtest"],
                   unlock: "Knob-gated via p146 (absent knob = v3.4 byte-identical). PANIC-POSSIBLE; one tap per force-quit; proxy-class until a kread pairs."),

        ChainStage(id: "sF2", index: 4,
                   title: "Stage-B pid-entitle widen",
                   goal: "The 8739b14 law: the ANE consumer validates the REQUEST-SUPPLIED pid's entitlements. p044_proc_idx.txt=<decimal> overrides procIdx (consumed file). The auto-arm's proc census is sandbox-denied on this build (proc_listallpids), so push a literal pid. Receipt class = the consumer accepting feature classes the stock sandbox cannot request (bigger geometries on the output-record lane).",
                   moduleIDs: ["p044"],
                   unlock: "Entitlement-map widening only — not uid, csflags, or trust cache. hasKread unchanged."),

        ChainStage(id: "sF3", index: 5,
                   title: "v63 guest-loop capstone",
                   goal: "The chosen-content cross-process proof. GUEST install: p146+p044 = GUEST HOLD (0x4b1d-tiled surface, sid stamped to the pasteboard). STANDALONE: p146 consumes p044_sid=<n> into p044_target.txt (marker parse first), p044 fires the copyout model at the guest's surface — target_pre.bin must show 0x4b1d (the round-trip gate) — then GUEST p146+p044 = OBSERVE. Guest-side base u16 = 0x5eaf = the cross-process chosen-content write.",
                   moduleIDs: ["p146", "p044"],
                   unlock: "RUN AS INDIVIDUAL TAPS, not this Run button — the sequence fires BOTH modules in ONE install, but the handoff needs the GUEST install's p146. No clipboard churn between the two p146 taps. One fire per fresh boot per install."),

        ChainStage(id: "sF4", index: 6,
                   title: "Desc-consume conversion",
                   goal: "p130 crossed the translation bar tonight: forged-type send ACCEPTED (kr=0), recv desc_count=1. The conversion door is the CONSUME path — note 118 field math: type==0 never forms from {sid,0xcN,1,1}, so the send-side record shape is not the forge; the descs tile at body+0x1c..0x64 is where a wrong-typed descriptor must be formed for the translator to follow. The p110/p114 serializer record fields are the live observables while the consume shape is hunted.",
                   moduleIDs: ["p114", "p110"],
                   unlock: "A desc-type conversion lands on a port object — the highest-value single write in the fleet. RE work, not a dial."),
        ChainStage(id: "s0", index: 7,
                   title: tl("权限面测绘"),
                   goal: tl("确定该构建上的实际起点：进程持有哪些 entitlement、沙盒放行到哪一层、mach 命名空间如何组织。后续每一步的收益都要以该基线折算。"),
                   moduleIDs: ["probe.privset", "kern.baseline"],
                   unlock: tl("缺少该基线，无法区分「漏洞所得」与「签名所授」。")),

        ChainStage(id: "s1", index: 8,
                   title: tl("信息泄露"),
                   goal: tl("先取得地址与内容。decmpfs 欠产出将内核页缓冲尾部交回用户态；TIFF 截断条带与 EXIF 短读将进程堆残留交回图像与元数据；CoreMedia bytestream 与 sandbox_extension 越过沙盒边界取回文件内容。"),
                   moduleIDs: ["kern.decmpfs", "iio.tiff.trunc", "iio.jpeg.comment",
                               "cm.fdleak", "sbx.toctou"],
                   unlock: tl("在取得稳定泄露之后，才有条件讨论将溢出写成什么值；否则只能触发崩溃。")),

        ChainStage(id: "s2", index: 9,
                   title: tl("溢出阈值标定"),
                   goal: tl("Type-5 阴影的写入是值可控的，但短溢出会被相邻 VLA 吸收。逐级抬升 R，确定该构建上栈布局开始失效的维度。"),
                   moduleIDs: ["cg.shading.sweep"],
                   unlock: tl("该阈值决定后续所有负载的长度预算。")),

        ChainStage(id: "s3", index: 10,
                   title: tl("值可控写"),
                   goal: tl("在标定所得长度上，以 PDF 中选定的 double 位模式决定被覆盖的指针。崩溃地址即证据 —— 它证明写入内容由攻击者控制，而非仅证明发生了崩溃。"),
                   moduleIDs: ["cg.shading"],
                   unlock: tl("值可控写与地址泄露相加，构成构造可控状态的全部要素；所缺的是将写转为执行的环节。")),

        ChainStage(id: "s4", index: 11,
                   title: tl("内核面"),
                   goal: tl("用户态可触及的内核入口数量有限。ipc_port 请求表索引竞态无 entitlement 门槛；decmpfs 已在泄露层验证。本层度量的是「能否将用户态的错误转为内核侧的状态变化」。"),
                   moduleIDs: ["kern.ipc"],
                   unlock: tl("需达到可复现阈值；低于该阈值时，越狱路径不成立。")),

        ChainStage(id: "s5", index: 12,
                   title: tl("解析器面"),
                   goal: tl("libarchive 的 2 字节堆越界与 CoreMedia 的 28 字节结构体外写，是整套中仅有的两个「写穿过对象边界」的形状。前者精确但浅，后者深且落在保存寄存器区。同一 CVE 下的 CAB 站点与 GPT 分区名越界读一并标定。"),
                   moduleIDs: ["arc.iso.stress", "arc.cab", "cm.rpu.sweep", "kext.gpt"],
                   unlock: tl("两者都需要稳定的堆布局控制，而这正是上一阶段泄露所提供的。")),

        ChainStage(id: "s6", index: 13,
                   title: tl("工具链落地"),
                   goal: tl("将上述产物转为可用形式：IPA 改包、二进制注入、字节级替换、属性改写、数据库读取。本层不依赖任何漏洞，但它是「漏洞能力」最终交付到手上的形态。"),
                   moduleIDs: ["tool.ipa", "tool.zip", "tool.hex", "tool.macho", "tool.paths"],
                   unlock: tl("自检全绿意味着工具链本身可信 —— 此后出现的问题是选择问题，不是工具问题。")),
    ]

    static func modules(for stage: ChainStage) -> [ExploitModule] {
        stage.moduleIDs.compactMap { Catalog.byID[$0] }
    }
}

struct ChainView: View {
    @EnvironmentObject private var engine: LabEngine

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    ForEach(ChainPlan.stages) { stage in
                        stageCard(stage)
                    }
                }
                .padding(16)
            }
            .luminaCanvas()
            .navigationTitle(t("chain.title"))
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func stageCard(_ stage: ChainStage) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 8) {
                    Text("\(stage.index)")
                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                        .foregroundColor(T.ember)
                        .frame(width: 20, height: 20)
                        .background(Circle().fill(T.ember.opacity(0.16)))
                    Text(stage.title)
                        .font(.system(size: 15, weight: .semibold, design: .rounded))
                        .foregroundColor(.white)
                    Spacer()
                }
                Text(stage.goal)
                    .font(T.body)
                    .foregroundColor(.white.opacity(0.66))
                    .fixedSize(horizontal: false, vertical: true)

                ForEach(ChainPlan.modules(for: stage)) { module in
                    HStack(spacing: 8) {
                        Circle()
                            .fill(engine.journal.verdict(for: module.id).tint)
                            .frame(width: 5, height: 5)
                        Text(module.title).font(T.monoSm).foregroundColor(.white.opacity(0.55))
                            .lineLimit(1)
                        Spacer()
                        Text(engine.journal.verdict(for: module.id).label)
                            .font(T.monoSm)
                            .foregroundColor(engine.journal.verdict(for: module.id).tint)
                    }
                }

                Text("→ " + stage.unlock)
                    .font(T.tiny)
                    .foregroundColor(.white.opacity(0.34))
                    .fixedSize(horizontal: false, vertical: true)

                RunButton(title: t("chain.stage.run"), systemImage: "play.fill", tint: T.ember) {
                    engine.runSequence(ChainPlan.modules(for: stage), label: stage.title)
                }
            }
        }
    }
}

// MARK: - File preview
//
// UITextView, not SwiftUI Text: a 65 KB TAP log / latin1-decoded binary in one
// Text() jetsams the Files tab. Load happens per-tab, on a background queue.

struct SafeLogView: UIViewRepresentable {
    let text: String
    var fontSize: CGFloat = 11

    func makeUIView(context: Context) -> UITextView {
        let v = UITextView()
        v.isEditable = false
        v.isSelectable = true
        v.backgroundColor = .clear
        v.textColor = UIColor.white.withAlphaComponent(0.82)
        v.font = UIFont.monospacedSystemFont(ofSize: fontSize, weight: .regular)
        v.textContainerInset = UIEdgeInsets(top: 10, left: 10, bottom: 10, right: 10)
        v.alwaysBounceVertical = true
        v.adjustsFontForContentSizeCategory = false
        v.dataDetectorTypes = []
        return v
    }

    func updateUIView(_ v: UITextView, context: Context) {
        if v.text != text { v.text = text }
    }
}

struct FilePreviewView: View {
    let item: FileItem
    @EnvironmentObject private var browser: FileBrowser
    @Environment(\.dismiss) private var dismiss
    @State private var mode = 0
    @State private var text: String?
    @State private var hex: String?
    @State private var info: [(String, String)] = []
    @State private var editing = false
    @State private var draft = ""
    @State private var status = ""
    @State private var copied = false
    @State private var packageEntries: [PackageEntry] = []
    @State private var thumb: UIImage?
    @State private var loading = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("", selection: $mode) {
                    Text(t("files.info")).tag(0)
                    Text(t("files.text")).tag(1)
                    Text(t("files.hex")).tag(2)
                    Text(t("files.package")).tag(3)
                }
                .pickerStyle(.segmented)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .onChange(of: mode) { _, _ in loadTab() }

                if !status.isEmpty {
                    Text(status).font(T.monoSm)
                        .foregroundColor(status.hasPrefix("✓") ? T.good : T.warn)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 16).padding(.bottom, 6)
                }

                if loading {
                    ProgressView().tint(T.ember).padding(.top, 20)
                    Spacer()
                } else {
                    pane
                }
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(item.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    if mode == 1 && browser.writable && (text?.count ?? 0) < 24_000 {
                        Button(editing ? t("files.cancel") : t("files.save")) {
                            if editing { save() } else { editing = true; draft = text ?? "" }
                        }.tint(T.ember)
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    HStack {
                        Button {
                            copyCurrent()
                        } label: {
                            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                        }.tint(T.ember)
                        Button(t("module.close")) { dismiss() }.tint(T.ember)
                    }
                }
            }
            .onAppear {
                info = browser.fileInfo(item)
                loadTab()
            }
        }
    }

    @ViewBuilder
    private var pane: some View {
        switch mode {
        case 0:
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Card {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(info.enumerated()), id: \.offset) { _, row in
                                KeyValueRow(key: row.0, value: row.1)
                            }
                        }
                    }
                    if let thumb {
                        Image(uiImage: thumb)
                            .resizable()
                            .scaledToFit()
                            .frame(maxHeight: 240)
                            .cornerRadius(10)
                    }
                    Text("Screen shows a tail. Copy puts up to 256 KB on the pasteboard. Huge TAP logs stay in Documents.")
                        .font(T.tiny)
                        .foregroundColor(.white.opacity(0.35))
                        .padding(.horizontal, 4)
                }
                .padding(16)
            }
        case 1:
            if editing {
                TextEditor(text: $draft)
                    .font(.system(size: 11, design: .monospaced))
                    .scrollContentBackground(.hidden)
                    .background(T.panelHi)
                    .padding(8)
            } else {
                SafeLogView(text: text ?? "—")
            }
        case 2:
            SafeLogView(text: hex ?? "—", fontSize: 10)
        default:
            ScrollView {
                VStack(alignment: .leading, spacing: 3) {
                    if packageEntries.isEmpty {
                        Text("—").font(T.monoSm).foregroundColor(.white.opacity(0.4))
                    } else {
                        ForEach(packageEntries.prefix(300)) { e in
                            Text("\(e.name)  \(e.size) B")
                                .font(T.monoSm)
                                .foregroundColor(.white.opacity(0.6))
                                .lineLimit(1)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
            }
        }
    }

    private func copyCurrent() {
        let body: String
        switch mode {
        case 2:
            body = hex ?? FileLoader.hexDump(at: item.path, limit: 4096) ?? ""
        default:
            body = FileLoader.tail(at: item.path, maxBytes: FileLoader.copyCap) ?? text ?? ""
        }
        UIPasteboard.general.string = body
        copied = true
        status = "✓ copied \(body.count) chars"
    }

    private func loadTab() {
        let path = item.path
        let size = item.size
        let tab = mode
        loading = (tab != 0)
        DispatchQueue.global(qos: .userInitiated).async {
            var preview: String?
            var dump: String?
            var pkg: [PackageEntry] = []
            var image: UIImage?
            switch tab {
            case 1:
                preview = FileLoader.previewText(at: path, maxBytes: FileLoader.screenCap)
                    ?? "[binary \(size) B — Hex tab / Copy tail]"
            case 2:
                dump = FileLoader.hexDump(at: path, limit: 2048)
            case 3:
                if PackageTool.isZip(path) { pkg = PackageTool.list(path) }
            default:
                if FileLoader.kind(of: path) == .image {
                    image = UIImage(contentsOfFile: path)
                    if let raw = image, raw.size.width > 800 || raw.size.height > 800 {
                        let scale = min(800 / raw.size.width, 800 / raw.size.height)
                        let sz = CGSize(width: raw.size.width * scale, height: raw.size.height * scale)
                        UIGraphicsBeginImageContextWithOptions(sz, false, 1)
                        raw.draw(in: CGRect(origin: .zero, size: sz))
                        image = UIGraphicsGetImageFromCurrentImageContext()
                        UIGraphicsEndImageContext()
                    }
                }
            }
            DispatchQueue.main.async {
                if tab == 1 { text = preview }
                if tab == 2 { hex = dump }
                if tab == 3 { packageEntries = pkg }
                if tab == 0 { thumb = image }
                loading = false
            }
        }
    }

    private func save() {
        // Validate a plist before writing so a typo cannot break a preference file.
        if item.name.hasSuffix(".plist") {
            guard let data = draft.data(using: .utf8),
                  (try? PropertyListSerialization.propertyList(from: data, format: nil)) != nil else {
                status = tl("plist 语法错误，未写入")
                return
            }
        }
        let backup = item.path + ".cinder27.bak"
        if !FileManager.default.fileExists(atPath: backup) {
            try? FileManager.default.copyItem(atPath: item.path, toPath: backup)
        }
        do {
            try Container.write(Data(draft.utf8), to: item.path)
            status = "✓ \(t("files.save")) · \(t("files.backup"))"
            text = draft
            editing = false
            browser.reload()
        } catch {
            status = Container.describe(errno)
        }
    }
}

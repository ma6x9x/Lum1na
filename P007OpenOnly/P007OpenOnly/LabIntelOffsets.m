//
//  LabIntelOffsets.m
//  Merged intel offset database. Reference only - see LabIntelOffsets.h.
//
//  Sources:
//   - PROVEN: Lum1na LabOff tables + on-device runs (P053/P063/P065/P069,
//     cs2core rig proof 2026-10-14).
//   - LADDER: Dopamine 3.0.11 BaseBin/libjailbreak/src/info.c (opa334),
//     darwin-version branches, exact lines.
//   - LEAD: DarkSword chain_loader_26.js __A14_A18_OFFSETS (leaked kit,
//     unverified by us).
//

#import "LabIntelOffsets.h"

#import <stdio.h>
#import <string.h>

const LabIntelEntry LabIntelTab[] = {
    // ---- PROVEN: Lum1na on-device ----
    { "a14_23f77.static_base",      "iPhone13,* 23F77",       0xFFFFFFF007004000ULL, "PROVEN", "LabOff runtime table" },
    { "a13_22g100.static_base",     "iPhone12,1 22G100",      0xFFFFFFF007004000ULL, "PROVEN", "LabOff runtime table (link base)" },
    { "a13_22g100.kbase.live",      "iPhone12,1 22G100",      0xFFFFFFF01C448000ULL, "PROVEN", "cs2core rig run 2026-10-14, magic PASS" },
    { "a13_22g100.kslide.live",     "iPhone12,1 22G100",      0x15444000ULL,         "PROVEN", "cs2core rig run 2026-10-14" },
    { "p063.aio_pin",               "A14 23F77",              0xFFFFFFF00A285E94ULL, "PROVEN", "P063 aio84530 kn_sdata pin" },
    { "p053.necp_client_add",       "A14 23F77",              0xFFFFFFF00A0C0810ULL, "PROVEN", "P053 NECP race map" },
    { "p053.necp_add_flow",         "A14 23F77",              0xFFFFFFF00A0C2AD0ULL, "PROVEN", "P053 NECP race map" },
    { "p069.dma_command",           "A14 23F77",              0xFFFFFFF00A507DBCULL, "PROVEN", "P069 IOGPU DMA command map" },
    { "p069.make_mapping",          "A14 23F77",              0xFFFFFFF00A512314ULL, "PROVEN", "P069 IOGPU makeMapping" },
    { "p065.trap_selector",         "A14 23F77",              0xFFFFFFF0095C84F0ULL, "PROVEN", "P065 Facet A trap selector" },

    // ---- LADDER: Dopamine libjailbreak info.c ----
    { "socket.usecount",            "darwin<23.4",            0x24c,                 "LADDER", "info.c base branch" },
    { "socket.usecount",            "darwin>=23.4,<25",       0x254,                 "LADDER", "info.c iOS 17.4+ branch; rig darwin 24.6.0" },
    { "socket.usecount",            "darwin>=25 (iOS 26+)",   0x23c,                 "LADDER", "info.c iOS 26.0+ branch" },
    { "inpcb.icmp6filt",            "all (info.c)",           0x148,                 "LADDER", "info.c" },
    { "inpcb.chksum",               "all (info.c)",           0x150,                 "LADDER", "info.c" },
    { "socket.proto",               "darwin>=23.4",           0x20,                  "LADDER", "info.c" },
    { "TFRO_HARDENED",              "darwin>=23.4,<25",       0x100,                 "LADDER", "info.c" },
    { "TFRO_HARDENED",              "darwin>=25 (iOS 26+)",   0x0,                   "LADDER", "info.c iOS 26.0+ branch" },
    { "TFRO_PLATFORM",              "darwin>=25 (iOS 26+)",   0x80,                  "LADDER", "info.c" },
    { "IOSurface.memoryDescriptor", "darwin>=23.4",           0x30,                  "LADDER", "info.c" },
    { "pmap.txm_address_space",     "SPTM darwin>=24,<25",    0xA8,                  "LADDER", "info.c iOS 18+ SPTM" },
    { "pmap.txm_address_space",     "SPTM darwin>=25",        0x98,                  "LADDER", "info.c iOS 26.0+" },
    { "pmap.asid",                  "SPTM darwin>=24",        0x88,                  "LADDER", "info.c" },
    { "pmap.type",                  "SPTM darwin>=24",        0x94,                  "LADDER", "info.c" },
    { "task.can_transfer_ownership","darwin>=25 (iOS 26+)",   0x560,                 "LADDER", "info.c, plus taskJitboxAdjust" },
    { "TXMAddressSpace.codeRegions","darwin>=25 (iOS 26+)",   0x28,                  "LADDER", "info.c" },
    { "TXMAddressSpace.allowInval", "darwin>=25 (iOS 26+)",   0x30,                  "LADDER", "info.c" },

    // ---- LEAD: DarkSword chain_loader_26.js __A14_A18_OFFSETS ----
    // ios18 family claims A14/A15/A16/A17 Pro on iOS 18.
    { "kernproc",                   "DS ios18 A14-A17Pro",    0xFFFFFFF007D2C258ULL, "LEAD",   "chain_loader_26.js" },
    { "current_proc",               "DS ios18 A14-A17Pro",    0xFFFFFFF009E646D4ULL, "LEAD",   "chain_loader_26.js" },
    { "proc_find",                  "DS ios18 A14-A17Pro",    0xFFFFFFF00A2BBD44ULL, "LEAD",   "chain_loader_26.js" },
    { "proc_rele",                  "DS ios18 A14-A17Pro",    0xFFFFFFF0083A01E0ULL, "LEAD",   "chain_loader_26.js" },
    { "copyin",                     "DS ios18 A14-A17Pro",    0xFFFFFFF009DAECB0ULL, "LEAD",   "chain_loader_26.js" },
    // ios26 family claims A18/A18 Pro/A19 on iOS 26.
    { "kernproc",                   "DS ios26 A18-A19",       0xFFFFFFF007D2C258ULL, "LEAD",   "chain_loader_26.js" },
    { "allproc",                    "DS ios26 A18-A19",       0xFFFFFFF007C8CBB8ULL, "LEAD",   "chain_loader_26.js" },
    { "kernel_task",                "DS ios26 A18-A19",       0xFFFFFFF007D2D140ULL, "LEAD",   "chain_loader_26.js" },
    { "vm_kernel_map",              "DS ios26 A18-A19",       0xFFFFFFF007D2C828ULL, "LEAD",   "chain_loader_26.js" },
    // Struct offsets, both DS families claim the same values.
    { "proc.p_ucred",               "DS A14-A19 structs",     0x28,                  "LEAD",   "chain_loader_26.js" },
    { "proc.p_pid",                 "DS A14-A19 structs",     0x60,                  "LEAD",   "chain_loader_26.js" },
    { "proc.p_task",                "DS A14-A19 structs",     0x08,                  "LEAD",   "chain_loader_26.js" },
    { "proc.p_csflags",             "DS A14-A19 structs",     0x24,                  "LEAD",   "chain_loader_26.js ios26: two-step proc+0x18 -> proc_ro+0x28" },
    { "ucred.cr_uid",               "DS A14-A19 structs",     0x18,                  "LEAD",   "chain_loader_26.js" },
    { "ucred.cr_ruid",              "DS A14-A19 structs",     0x1c,                  "LEAD",   "chain_loader_26.js" },
    { "task.map",                   "DS A14-A19 structs",     0x28,                  "LEAD",   "chain_loader_26.js" },
    { "task.itk_space",             "DS A14-A19 structs",     0xc0,                  "LEAD",   "chain_loader_26.js" },
    // Packed source we have not read yet:
    { "agx.26x.offsets",            "sbx0_26x_agx_offsets",   0,                     "LEAD-PACKED", "obfuscator.io packed, queued for unpack" },
    // OUR OWN Ghidra derivation, 2026-10-14, exact SKU/build: T8101 xnu-12377.122.4
    // (hunt iPhone13,2 26.5 / A14_23F77). proc_iterate + proc_list_add decompiled:
    // head walk p = *(p) (le_next +0x0), le_prev +0x8 of first member == &head,
    // pid at proc+0x60 (p[0xc]), proc_ro at proc+0x18 with proc_ro->proc backref @0.
    // status GHIDRA = static decompile proof on this exact build; live CONFIRM still
    // pending a kread lane on 26.5 (write lanes PARKED). Reference-only per header.
    { "allproc",                    "Ghidra T8101 12377",     0xFFFFFFF00A900770ULL, "GHIDRA", "proc_iterate+proc_list_add decompile, kbase 0x7004000, delta 0x38FC770" },
    { "zombproc",                   "Ghidra T8101 12377",     0xFFFFFFF00A900778ULL, "GHIDRA", "proc_iterate second head (param_1 bit1), delta 0x38FC778" },
    { "kernprocvar",                "Ghidra T8101 12377",     0xFFFFFFF007B6EB30ULL, "GHIDRA", "struct proc *kernproc var (runtime value = &proc0); in.c:471 assert + proc_list_add parent check" },
    { "kernprocvar",                "Ghidra A13_22G100",      0xFFFFFFF007ADE3A8ULL, "GHIDRA", "kernproc slot (value=&proc0); in.c:0x476 assert compare + skywalk.c:0x37b + fork1 ppid readback, xnu-11417.140.69 T8030. SLOT: deref once to proc0 (P094 isKv)" },
    { "allproc",                    "Ghidra A13_22G100",      0xFFFFFFF00A653CB8ULL, "GHIDRA", "8-byte LIST_HEAD; fork register LIST_INSERT_HEAD verbatim (le_next+0 le_prev+8 pid+0x60 pptr+0x10), delta 0x364FCB8" },
    { "zombproc",                   "Ghidra A13_22G100",      0xFFFFFFF00A653CC0ULL, "GHIDRA", "8-byte LIST_HEAD; exit1 remove + zombie LIST_INSERT_HEAD verbatim; allproc+8" },
    { "initproc",                   "Ghidra A13_22G100",      0xFFFFFFF00A6542C0ULL, "GHIDRA", "initproc slot; fork register parent==initproc child-flag + exit1 reparent checks" },
    { "gRegistryRoot",              "Ghidra T8101 12377",     0xFFFFFFF00A934FF8ULL, "GHIDRA", "IORegistryEntry *gRegistryRoot VAR SLOT (value = kalloc'd 0x28 root instance); getRegistryRoot kalloc_data+store; updateConsoleUsers passes instance as messageArgument (CVE-2026-65371 leak)" },

    // ---- LADDER: Dopamine info.c iOS 26.0+ / 26.4+ / 27.0+ (2026-10-15 mine) ----
    { "ipc_space.table",            "darwin>=25 (iOS 26+)",   0x48,                  "LADDER", "info.c iOS 26.0+ branch" },
    { "ipc_port.kobject",           "darwin>=25 (iOS 26+)",   0x50,                  "LADDER", "info.c iOS 26.0+ branch" },
    { "IOMachPort.object",          "darwin>=25 (iOS 26+)",   0x20,                  "LADDER", "info.c iOS 26.0+ branch" },
    { "vm_map_entry.user_debug",    "darwin>=25 (iOS 26+)",   27,                    "LADDER", "info.c iOS 26.0+ branch (bit index)" },
    { "pmap.asid",                  "SPTM darwin>=25.4",      0x6c,                  "LADDER", "info.c iOS 26.4+ SPTM (A13/A14 TXM iOS27 adjust -8)" },
    { "pmap.txm_address_space",     "SPTM darwin>=25.4",      0x88,                  "LADDER", "info.c iOS 26.4+ SPTM (A13/A14 TXM iOS27 adjust -8)" },
    { "vm_map.hdr",                 "darwin>=25.4",           0x18,                  "LADDER", "info.c iOS 26.4+ branch" },
    { "vm_map.flags",               "darwin>=25.4",           0xE8,                  "LADDER", "info.c iOS 26.4+ branch" },
    { "vm_map_header.first",        "darwin>=25.4",           0x0,                   "LADDER", "info.c iOS 26.4+ branch" },
    { "vm_map_header.nentries",     "darwin>=25.4",           0x28,                  "LADDER", "info.c iOS 26.4+ branch" },
    { "vm_map_entry.flags",         "darwin>=25.4",           0x38,                  "LADDER", "info.c iOS 26.4+ branch" },
    { "PVH_TYPE_MASK",              "darwin>=27 (iOS 27)",    0x7,                   "LADDER", "info.c iOS 27.0+ branch (A19 27.0 struct offsets)" },
    { "PVH_HIGH_FLAGS",             "darwin>=27 (iOS 27)",    0x64C0000000000000ULL, "LADDER", "info.c iOS 27.0+ branch" },
    { "vm_map.hdr",                 "darwin>=27 (iOS 27)",    0x0,                   "LADDER", "info.c iOS 27.0+ branch" },
    { "vm_map.flags",               "darwin>=27 (iOS 27)",    0xB0,                  "LADDER", "info.c iOS 27.0+ branch" },
    { "vm_map_entry.prev",          "darwin>=27 (iOS 27)",    0x4,                   "LADDER", "info.c iOS 27.0+ (packed entries)" },
    { "vm_map_entry.flags_prot",    "darwin>=27 (iOS 27)",    4,                     "LADDER", "info.c iOS 27.0+ (bit index)" },
    { "vm_map_entry.user_debug",    "darwin>=27 (iOS 27)",    23,                    "LADDER", "info.c iOS 27.0+ (bit index)" },
    { "proc.flag",                  "darwin>=27 (iOS 27)",    0x444,                 "LADDER", "info.c iOS 27.0+ branch" },
    { "proc_ro.ucred",              "darwin>=27 (iOS 27)",    0x30,                  "LADDER", "info.c 27.0+: 0x28 base +0x8 shift; task_tokens REMOVED" },
    { "proc_ro.t_flags_ro",         "darwin>=27 (iOS 27)",    0x88,                  "LADDER", "info.c 27.0+: 0x80 +0x8" },
    { "vm_page.pv_head",            "SPTM darwin>=27",        0x30,                  "LADDER", "info.c iOS 27.0+ SPTM branch" },
    { "vm_page.struct_size",        "SPTM darwin>=27",        0x40,                  "LADDER", "info.c iOS 27.0+ SPTM branch" },

    // ---- GHIDRA-EXT: 24A435 iOS 27.0 GM iPhone17,5 (A19 Pro class) audit ----
    // GOLDMINE 26.5 drop, external static audit. NOT our silicon, NOT our
    // build — reference anchors for the 27.0 A19 port; twin before trusting.
    { "ave2.signed_product_loop",   "Ghidra-ext 24A435 A19",  0xFFFFFFF00886B170ULL, "GHIDRA-EXT", "27GM AppleAVE2: n=(s8)s->[0x18c]*(s8)s->[0x18d] as read bound, no size relation; caller 0xfffffff00886bf0c" },
    { "ave2.uc_dispatch_gm",        "Ghidra-ext 24A435 A19",  0xFFFFFFF008876E4CULL, "GHIDRA-EXT", "27GM AVE2 UC dispatch (unique in kext); REPORT_AVE_84607" },
    { "ave2.enctype_guard_fn",      "Ghidra-ext 24A435 A19",  0xFFFFFFF0087348A8ULL, "GHIDRA-EXT", "27GM EncType-vs-session guard fn (cmp w8,w9 at +0x474); ABSENT on 23F77 until proven" },
    { "iomd.dmaref_map_worker",     "Ghidra-ext 24A435 A19",  0xFFFFFFF00B345FECULL, "GHIDRA-EXT", "27GM IOMD map worker acquires via UNCHECKED retain helper" },
    { "iomd.dmaref_retain_unchecked","Ghidra-ext 24A435 A19", 0xFFFFFFF00B34612CULL, "GHIDRA-EXT", "27GM IOMD RETAIN helper, unbounded +0x34 increment" },
    { "iomd.op6_release_gated",     "Ghidra-ext 24A435 A19",  0xFFFFFFF00B34572CULL, "GHIDRA-EXT", "27GM op-6 release: [x0+0x98]==0 -> RELEASE SKIPPED" },
    { "decmpfs.zlib_guard",         "Ghidra-ext 24A435 A19",  0xFFFFFFF008B9D4B0ULL, "GHIDRA-EXT", "27GM AppleFSCompressionTypeZlib overflow idiom — CORRECT, do not redo" },
    { "avd.mvhevc_release_unused",  "Ghidra-ext 24A435 A19",  0x22A382DFCULL,        "GHIDRA-EXT", "27GM AVD.videodecoder DAEMON signed index (b.le passes negatives; 64-entry table). userspace, not kernel" },

    // ---- LEAD: lockdownd 26.5 userspace logic map (ncxcy research) ----
    // USB/pairing class, NOT KRW. Unslid lockdownd image offsets.
    { "lockdownd.handle_start_session","ncxcy lockdownd 26.5", 0x10001F8C8ULL,       "LEAD", "startsession: missing lastpaireddate skips 30-day expiry" },
    { "lockdownd.ssl_setup",        "ncxcy lockdownd 26.5",   0x1000AC4F8ULL,        "LEAD", "_SSLSetEnableCertVerify(ctx,0); trust anchor = pair-record rootcertificate" },
    { "lockdownd.is_host_trusted",  "ncxcy lockdownd 26.5",   0x100019CA8ULL,        "LEAD", "IgnoreUntrustedList=YES in unauthenticated options skips blocklist" },
    { "lockdownd.parse_message",    "ncxcy lockdownd 26.5",   0x10001C61CULL,        "LEAD", "ACL mask 0x1E604: unpaired getvalue/getvaluecu/removevalue; code 23 (v8>0x10) skips check" },
    { "lockdownd.load_pair_record", "ncxcy lockdownd 26.5",   0x100016160ULL,        "LEAD", "hostid traversal: only leading '..' rejected -> arbitrary plist as pair record" },
    { "lockdownd.getvalue_keybag",  "ncxcy lockdownd 26.5",   0x10000C960ULL,        "LEAD", "unpaired BFU/AFU + keybag lock state leak" },
    { "lockdownd.scprefs_8021x",    "ncxcy lockdownd 26.5",   0x10000A2C0ULL,        "LEAD", "post-session SCPreferences write, no auth check" },
    { "lockdownd.scprefs_cltm",     "ncxcy lockdownd 26.5",   0x10000A570ULL,        "LEAD", "post-session SCPreferences write, no auth check" },
    { "lockdownd.braa_cluster",     "ncxcy lockdownd 26.5",   0x100006BFCULL,        "LEAD", "8x braa vtable dispatch 0x100006bfc-0x100006cc0; PAC forgery needs x2 control" },

    // ---- GHIDRA-EXT: 24A435 T8150 exact-build sweep (2026-10-26 night, note 266 §P) ----
    { "t8150.sysent",           "Ghidra-ext 24A435 T8150", 0xFFFFFE0007EAEE90ULL, "GHIDRA-EXT", "BSD sysent: stride 16, ~558 entries (limit 0x22e); auth-fn hi words 0x8010/8020/8030; tiny cluster 0xad83464/74/8c; [21]=0xadca020 [24]=0xadcf500" },
    { "t8150.iogpu_smethods_a", "Ghidra-ext 24A435 T8150", 0xFFFFFE00082F64B0ULL, "GHIDRA-EXT", "IOGPUDeviceUserClient sMethods A: 56 entries sel0..0x37 stride 0x18; table B 0x82f69f0; choice = [uc+0x103] bit0" },
    { "t8150.iogpu_dispatch",   "Ghidra-ext 24A435 T8150", 0xFFFFFE000A024D94ULL, "GHIDRA-EXT", "getTargetAndMethodForIndex; gate [uc+0x100] bit0 else 0xE00002D8" },
    { "t8150.s_submit_buffers", "Ghidra-ext 24A435 T8150", 0xFFFFFE000A02299CULL, "GHIDRA-EXT", "s_submit_command_buffers = sel 0x24 (idx 36) on 24A435 — Rocket's 17.x sel 0x1A does NOT carry; sel26 = 0xa022c2c single-resource" },
    { "t8150.rock_keys_1_3",    "Ghidra-ext 24A435 T8150", 0xFFFFFE000A02C3C0ULL, "GHIDRA-EXT", "Rocket battery CONFIRMED: owner=0x120, submitObject=0x28, resObjMemory=0x30 (site 0xa02c3c0); ioGpuUserClientTypeStatic=0x7f20260 (AGXDeviceUserClient-class nuance!)" },
    { "t8150.ave2_mapper",      "Ghidra-ext 24A435 T8150", 0xFFFFFE00087A4B4CULL, "GHIDRA-EXT", "AVE2 id->slot mapper (smell: raw id*8 offsets, no size check; only bound = ctx+0x110 AND). sole caller 0x8879dc8; configure 0x887660c validates NOTHING; thunk 0x8876968; sibling reader 0x87a450c" },
    { "sptm.022.remove_ctx_id", "SPTM 820.0.22 blob",      0xFFFFFFF0270B7AB0ULL, "GHIDRA-EXT", "UAT race fn (40.18-twin at -0x1c): casab ttbat-lock 0x…0b7b38 -> PTE stores 0x…0b7b88/90 -> dsb oshst -> tlbi 0x…0b7bf0 — NO Dekker gate/ish barrier = UNGATED on 24A435" },
    { "sptm.022.upd_unmap_sync","SPTM 820.0.22 blob",      0xFFFFFFF0270B8460ULL, "GHIDRA-EXT", "update_permissions_unmap_sync (twin -0x1c); prepare_fw_unmap_continue 0x…0b9594; root PTE writer 0x…0b80e4; issue_tlbi 0x…0b7ed0 (stub table 0x2701c6e8); map_continue 0x…0b9a90" },
    { "sptm.022.percpu",        "SPTM 820.0.22 blob",      0xFFFFFFF02709E1F8ULL, "GHIDRA-EXT", "mutation-path globals: +0x60 ttbat lock, +0x78 root table, +0x138 ctx array; per-CPU base = sysreg s3_6_c15_c11_1, flag byte +0x1628" },
    { "vfs.cluster_write",      "Ghidra-ext 24A435 T8150", 0xFFFFFE000AD67FB8ULL, "GHIDRA-EXT", "clustered-write pipeline (note 266 §G): contig-decider 0xad68b04 (bail PRESENT), copy path 0xad682a8, upl-uiomove 0xad6c398, copyin core 0xad14e28; vm_fault side still open" },
    { "t8150.physmap_dats",     "Ghidra-ext 24A435 T8150", 0xFFFFFE0007E59780ULL, "GHIDRA-EXT", "physmap aperture DATs (data-abort handler 0xad1cdd4): physmap 0x7e59780..0x7e58df8, static region 0x7e58e00..0x7e97b50; vm_page array 0x7e58010; NO gPhysBase strings on 27.x" },
    { "t8150.debugheader_fn",   "Ghidra-ext 24A435 T8150", 0xFFFFFE000AB55AF0ULL, "GHIDRA-EXT", "debug-header printer: chain head *(0x7ed30f0+0x60); prints Kernel slide + SPTM/TXM load addrs + UUIDs per entry; panic_decode upgrade candidate" },
    // ---- PROVEN-EXT: m2scaler iosaDiag leak (P098 implements) ----
    { "m2scaler.get_iosaDiag_sel",  "iOS<=26.5.2 (23F77 live)", 8,                   "PROVEN-EXT", "AppleM2ScalerCSCDriver sel 8; event_payload +0x18 leaks IOSurface KVA (MTE tag on A17+); fixed 26.6 (23G71); likely CVE-2026-64709" },
    // ---- AKS 65343 lane CLOSED on app-reach (2026-10-26 verification, re_aks23.md) ----
    { "aks23.dispatch_index",    "Ghidra 23F77 (AKS)",     0xFFFFFFF008D9F868ULL, "GHIDRA-EXT", "AKS 163-sel table: idx = RAWSEL-1 (subs w28,w1,#1)! raw sel 17 = idx 0x10 = 0x8d998f0 -> 0x8d9b95c -> 0x8d8ca10 -> ctor 0xa43e240 -> prepare_output_ool 0x8d88a68. raw 16 = idx 0xf = 0x8d99a20 (worker 0x8d8c010, GATED [uc+0xf0] bit4)" },
    { "aks23.copyout_bounded",   "Ghidra 23F77 (AKS)",     0xFFFFFFF008D88A68ULL, "GHIDRA-EXT", "65343's declared_length NOT trusted on 23F77: declared < vtable+0xa0 ret = 0x2db; ret OVERWRITES declared; copyout = kernel-computed len ONLY. no app-reachable OOB on this copyout" },
    { "aks23.acm_disconnected",  "Ghidra 23F77 (AKS)",     0xFFFFFFF008D72C78ULL, "GHIDRA-EXT", "AppleKeyStoreCommand 0x8d72c78 (the ONLY xref into the ACM deserializer chain) = ZERO image-wide refs on 23F77: the 65343 deserializer (0x8d5cc80) is NOT UC-reachable — daemon/secd-shape only. LANE CLOSED for app-reach" },

    // ---- IOMD 43684-family VERIFIED LIVE-SHAPED on 23F77 (2026-10-26, re_iomd23.md) ----
    { "iomd23.retain_unchecked",  "Ghidra 23F77",  0xFFFFFFF00A511624ULL, "GHIDRA-EXT", "IOMD dmaref RETAIN: ldaddh w9,#1,[x0+0x34] — u16 refcount at md+0x34, NO CEILING (2nd site 0xa515dc4). Fix NOT present on 23F77 — LANE LIVE-SHAPED" },
    { "iomd23.dec_underflow_panic","Ghidra 23F77",  0xFFFFFFF00A5116D0ULL, "GHIDRA-EXT", "dma-ref dec: ldaddh #-1 at +0x34; pre-0 = PANIC _dmaReferences-underflow (string 0xfffffff0070b27ec); old==1 → teardown 0x9f1975c" },
    { "iomd23.release_gated",     "Ghidra 23F77",  0xFFFFFFF00A515D60ULL, "GHIDRA-EXT", "op-6 release dispatcher (sel=byte2 w1): case-6 @0xa515f88 ldr w8,[x0,#0x98]; cbz -> RELEASE SKIPPED. [x0+0x98]=u32 mapped-16K-pg-count, computed in worker 0xa50737c, RESET 0 by unmap-arm 0xa5073c4. TWIN dispatcher 0xa511324 = UNGATED sel6 (panic-on-underflow!) — route must use 0xa515d60" },
    { "iomd23.gate_oracle",       "Ghidra 23F77",  0xFFFFFFF00A515D60ULL, "GHIDRA-EXT", "sel-2 (case 1) copies [x0+0x98] into out-struct +0xc = APP-VISIBLE gate-state readback (user-readable oracle)" },
    { "iomd23.make_mapping",      "Ghidra 23F77",  0xFFFFFFF00A512314ULL, "GHIDRA-EXT", "IOMemoryDescriptor_makeMapping (single BL caller 0xa51f9cc = the mapper side — next hop for the UC-reach chase). NO entitlement check in any lane fn = NO AMFI gate" },
    { "iomd23.pglist_alloc",      "Ghidra 23F77",  0xFFFFFFF00A5081ECULL, "GHIDRA-EXT", "ioGMD page-list array alloc: 16B/entry (bl kalloc 0x9e18728), entry-count u32 at sub+0xe8, freepool head 0xa903db0 — the UAF type-confusion target" },
};

const int LabIntelCount = (int)(sizeof(LabIntelTab) / sizeof(LabIntelTab[0]));

uint64_t LabIntelValue(const char *name, const char *family) {
    if (!name) return 0;
    for (int i = 0; i < LabIntelCount; i++) {
        if (strcmp(LabIntelTab[i].name, name) != 0) continue;
        if (family && strcmp(LabIntelTab[i].family, family) != 0) continue;
        return LabIntelTab[i].value;
    }
    return 0;
}

void LabIntelEmitLines(void (^line)(const char *)) {
    if (!line) return;
    char buf[256];
    for (int i = 0; i < LabIntelCount; i++) {
        snprintf(buf, sizeof(buf), "%-26s %-24s %016llx %-12s %s",
                 LabIntelTab[i].name, LabIntelTab[i].family,
                 (unsigned long long)LabIntelTab[i].value,
                 LabIntelTab[i].status, LabIntelTab[i].source);
        line(buf);
    }
}
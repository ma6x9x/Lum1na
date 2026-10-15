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

    // ---- PROVEN-EXT: m2scaler iosaDiag leak (P098 implements) ----
    { "m2scaler.get_iosaDiag_sel",  "iOS<=26.5.2 (23F77 live)", 8,                   "PROVEN-EXT", "AppleM2ScalerCSCDriver sel 8; event_payload +0x18 leaks IOSurface KVA (MTE tag on A17+); fixed 26.6 (23G71); likely CVE-2026-64709" },
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
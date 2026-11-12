//
//  SandboxRead.h — the P116 issue->swap->consume harness exposed as a
//  reusable service for the in-app terminal. One call = a full-file
//  out-of-container READ (chunked, capped) written into Documents.
//  Tokens never logged; read-only; no kernel claims (P116 law).
//

#import <Foundation/Foundation.h>

@interface LabSandboxRead : NSObject
/// Read `target` out-of-container through the NOFOLLOW TOCTOU and write the
/// bytes to Documents/sbx_<basename>. Returns a receipt dictionary:
///   path (String?), bytes (NSNumber), error (String?)
+ (NSDictionary<NSString *, id> * _Nonnull)dumpIntoDocuments:(NSString *)target
    NS_SWIFT_NAME(dump(intoDocuments:));

/// CS_DEBUGGED + dual-mapped RX/RW diagnostic (Henge substrate shape,
/// GPL-2.0+ Leviidev/Henge via ammaarreshi/WindowsiOS; no execution attempted).
+ (NSString *)jitProbe;
/// Bounded out-of-container read as a string (maxBytes, default 64 KB).
+ (NSString * _Nullable)read:(NSString *)target maxBytes:(NSUInteger)maxBytes
    NS_SWIFT_NAME(read(_:maxBytes:));
@end

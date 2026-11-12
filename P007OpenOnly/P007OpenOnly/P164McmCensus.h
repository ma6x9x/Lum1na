//  P164McmCensus.h — MCM container census + system-group pivots (p164).
//  Translated from the jbjflab filza27.2 MCM integration (MHA-C2/-C7/-C12/-C13/-C15
//  proofs, 24A5390f archive) and forcequitOS/worse_query; our own implementation.
//  Read-only census: enumerate containers per class, then resolve the documented
//  probe leases and LIST what lands. No writes; tokens never logged.

#import <Foundation/Foundation.h>

@interface P164McmCensus : NSObject
/// Read-only MCM census + system-group lease probes; returns the tap body.
+ (NSString *)tap;
@end

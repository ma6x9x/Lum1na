//
//  Lum1naBoard.h
//  Lum1na
//

#import <Foundation/Foundation.h>

@interface Lum1naBoard : NSObject

+ (instancetype)shared;
+ (NSString *)tap;
/// Live kread32(kbase)==MH_MAGIC_64. Occupancy / IPS slide / heap leak never pass.
+ (NSString *)tapKreadTest NS_SWIFT_NAME(tapKreadTest());

@property (nonatomic, readonly) NSString *machine;
@property (nonatomic, readonly) NSString *osversion;
@property (nonatomic, readonly) NSString *skuTag;
@property (nonatomic, readonly) NSString *sku;
@property (nonatomic, readonly) uint64_t staticBase;
@property (nonatomic, readonly) uint64_t kslide;
@property (nonatomic, readonly) uint64_t kbase;
@property (nonatomic, readonly) BOOL hasKread;
@property (nonatomic, readonly) BOOL hasKwrite;
@property (nonatomic, readonly) NSString *kreadSignal;
@property (nonatomic, readonly) NSArray<NSDictionary *> *leaks;

// KRW context storage for glue code
@property (nonatomic, assign) void *krwContext;

- (void)refreshIdentity;
- (void)recordHeapLeak:(uint64_t)va source:(NSString *)source;
- (void)recordCandidate:(uint64_t)va kind:(NSString *)kind source:(NSString *)source;
// Stage-progress row in leaks[] with no kernel VA. Keyed on event|kind; hits bump.
- (void)recordEvent:(NSString *)event
               kind:(NSString *)kind
             detail:(NSString *)detail
             source:(NSString *)source;
- (BOOL)commitSlide:(uint64_t)slide reason:(NSString *)reason;
- (NSString *)jsonDump;
- (void)resetLeaks;

@end

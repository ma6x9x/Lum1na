//
//  Lum1naBoard.h
//  Lum1na
//

#import <Foundation/Foundation.h>

@interface Lum1naBoard : NSObject

+ (instancetype)shared;
+ (NSString *)tap;

@property (nonatomic, readonly) NSString *machine;
@property (nonatomic, readonly) NSString *osversion;
@property (nonatomic, readonly) NSString *skuTag;
@property (nonatomic, readonly) uint64_t staticBase;
@property (nonatomic, readonly) uint64_t kslide;
@property (nonatomic, readonly) uint64_t kbase;
@property (nonatomic, readonly) BOOL hasKread;
@property (nonatomic, readonly) BOOL hasKwrite;
@property (nonatomic, readonly) NSArray<NSDictionary *> *leaks;

// KRW context storage for glue code
@property (nonatomic, assign) void *krwContext;

- (void)refreshIdentity;
- (void)recordHeapLeak:(uint64_t)va source:(NSString *)source;
- (void)recordCandidate:(uint64_t)va kind:(NSString *)kind source:(NSString *)source;
- (BOOL)commitSlide:(uint64_t)slide reason:(NSString *)reason;
- (NSString *)jsonDump;
- (void)resetLeaks;

@end

//
//  P159IOSurfaceAdjacency.h
//  P007OpenOnly
//
//  Read-only IOSurface adjacency probe (SurfHeist technique, MIT).
//  Creates 50 16 KB surfaces, looks for a 0x4000 delta pair, and reads a
//  bounded window past the second surface. No OOB writes.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P159IOSurfaceAdjacency : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END

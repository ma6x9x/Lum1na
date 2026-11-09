//
//  P160SandboxEscape.h
//  P007OpenOnly
//
//  Read-only MCM container_query escape probe (KAMUI technique, MIT).
//  Tries the class-13 part-domain traversal against absolute targets and
//  reports whether a sandbox token is issued. No files are modified; an
//  optional kernelcache dump is gated on Documents/lum1na_dump_kernelcache.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P160SandboxEscape : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END

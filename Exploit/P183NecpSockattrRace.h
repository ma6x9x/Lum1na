//
//  P183NecpSockattrRace.h — the necp_get_socket_attributes two-pass TOCTOU.
//  p183 v1. PANIC-POSSIBLE (armed only). Never sets hasKread.
//

#import <Foundation/Foundation.h>

@interface P183NecpSockattrRace : NSObject
+ (NSString *)tap;
@end

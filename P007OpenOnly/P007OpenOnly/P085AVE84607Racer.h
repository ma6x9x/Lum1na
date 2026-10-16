//
//  P085AVE84607Racer.h
//  CVE-2026-84607 Close-vs-async racer — P007 port of Lum1na P064 v4.
//
//  UNPARKED by owner decision 2026-10-10 (previous PARK was an earlier
//  agent's call; owner explicitly lifted it).
//
//  Gap (23F77, AppleAVE2 UC, fixed 26.7):
//   - AVE clientClose      0xFFFFFFF008371094
//   - AVE stopAsync        0xFFFFFFF008370174  (zeroes UC+0x160 under +0x158)
//   - AVE sendAsync        0xFFFFFFF00837137C  (uses +0x118/+0x160/+0xd8
//                                                WITHOUT the +0x158 lock)
//  P061/P066 proof: VTCompressionSessionCreate+Prepare+EncodeFrame work from
//  this IPA (H264+HEVC). P064 v3 device proof: PAC-trap SIGTRAP in CFRelease
//  from the vtcsr completion block = completion DELIVERED AFTER clientClose
//  = gap precondition PROVEN. UC lives in videocodecd.
//
//  Goal (panic-as-RE): kernel panic task=videocodecd, PC near 0x...137C /
//  0x...1094 — the ips then names the stale waiter's zone for free.
//  Client-side SIGTRAP crashes are EXPECTED gap signatures.
//  HONESTY: panic != hasKread. commitSlide stays gated.
//

#import <Foundation/Foundation.h>

@interface P085AVE84607Racer : NSObject
+ (NSString *)tap;
@end
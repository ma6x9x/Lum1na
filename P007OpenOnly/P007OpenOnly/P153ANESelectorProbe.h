//
//  P153ANESelectorProbe.h — ANE UC class-ID + DirectPath reach probe. p153.
//
//  Static map (23F77, capstone 2026-11-07):
//    H11ANEInUserClient       -> table1 (0x7cbfa30, 17 sels)
//        0 DeviceOpen 1 DeviceClose 2 SendRequest 3 ProgramCreate
//        4 ProgramPrepare 5 ProgramUnprepare 6 ProgramDestroy 7 GetStatus
//    H11ANEInDirectPathClient -> table2 (0x7cbfcd8, 9 sels)
//        0 DeviceOpen 1 DeviceClose 2 SendRequest 3 OutputSetEnqueue
//        4 InputsReady 5 MemoryMapRequest 6 MemoryUnMapRequest 7 SessionHint
//  Class ID by sel7 size: UserClient GetStatus = in 0 / out 0x20;
//  DirectPath SessionHint = in 0x10 / out 0x18. The mismatched shape is 2c2.
//
//  Nothing fires by default. p153_send=1 performs ONE async sel2 with a
//  zero-count 0x948 request (no prewire records -> cannot OOB) strictly as a
//  reach test. PANIC-POSSIBLE when send/map/create are enabled: one tap per
//  force-quit. This probe never sets counts above 0 unless the operator does.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P153ANESelectorProbe : NSObject
/// Knobs (Documents/p153_knobs.txt first, pasteboard fallback; key=value):
///   p153_t1=1 p153_t4=1        type 1 / type 4 on H11ANEIn
///   p153_send=0|1              async sel2 reach test (zero counts)
///   p153_map=0|1               sel5 MemoryMapRequest 0x2008 (DP class)
///   p153_create=0|1            sel3 ProgramCreate 0x20 (User class)
///   p153_in_count / p153_out_count / p153_off_in=0x1c / p153_off_out=0x51c
///   p153_create_size=0xd88 p153_create_magic=0xac738
///   p153_pid=<n>
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END

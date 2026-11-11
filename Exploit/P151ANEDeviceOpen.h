//
//  P151ANEDeviceOpen.h — ANE DirectPath DeviceOpen pid probe. p151 (v1, safe).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P151ANEDeviceOpen : NSObject
/// The first step of the 23F77 DirectPath ladder, decoded from the on-disk
/// dispatch table (two copies at 0x7cbfa30 / 0x7cbfcd8, stride 0x28):
///   sel 0 = DeviceOpen          structIn 0x68, structOut 0x68
///   sel 2 = ProgramSendRequest  1 scalar + structIn 0x948, structOut 0x28, async
///   sel 4 = ProgramPrepare      structIn/out 0x38
///
/// p071 showed sel0 with an all-zero struct returns 0xe00002f0, the
/// "Cannot find task from the given pid" branch. This probe fills the
/// DeviceOpen struct with a REAL pid at the four plausible offsets
/// (0x00, 0x0c, 0x10, 0x54) and reports the kr matrix + output bytes.
/// It never calls ProgramSendRequest and never builds a request.
///
/// pid source: pasteboard marker "p151_pid=<n>" (same no-push handoff law
/// as p146); absent = getpid(). A borrowed pid (aned) is the Stage-B test.
///
/// A kr=0 at any offset = DeviceOpen accepted the pid: the DirectPath
/// client is live and p152 (ProgramPrepare) / p153 (SendRequest) follow.
/// All 2f0 = the kernel still cannot resolve the pid (wrong offset, or the
/// pid's task is gone). 2c2 = struct size wrong. 2e2 = entitlement refuse.
+ (NSString *)tap;

/// v5: called from p044 IMMEDIATELY after the direct evaluate, when the ANE
/// is actually powered. Opens H11ANEIn/H1xANELoadBalancer type 1 and calls
/// sel0 DeviceOpen with getpid; returns the log rows. No send request.
+ (NSString *)probeInline;

/// v5 knobs (pasteboard or Documents/p151_knobs.txt): p151_type=<0..4> single
/// type, p151_sweep=0|1 (default 1 = types 0..4), p151_in=<bytes> (default 0x88),
/// p151_out=<bytes> (default 0x88), p151_off=<offset of the u32 pid, default 0>,
/// p151_pid=<pid> (default 0 = buffer stays zeroed), p151_qword=0|1 plus
/// p151_qoff=<offset> to also place the pid as a u64.
/// 24A435 law: sel0 is 0x88/0x88 and reads no pid; AddClient failure with
/// out[0]==0 still returns success. 23F77 law: sel0 is 0x68/0x68, pid is
/// log-only, and 2f0 is the client-registration miss.
@end

NS_ASSUME_NONNULL_END

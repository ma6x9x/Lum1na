//
//  P095UcredLadder.h
//  P007OpenOnly
//
//  READ-ONLY ucred ladder validation. Walks proc -> proc_ro -> ucred on the
//  live kernel and proves every write target the elevate step will hit,
//  BEFORE anything is written. Lab-app port of the official Lum1na
//  Exploit/P095UcredLadder (ma6x9x/Lum1na). Zero kernel writes.
//
//  Rungs: proc.proc_ro -> proc_ro.csflags -> ucred -> cr_posix (uid/ruid/
//  svuid/groups/rgid/svgid, cross-checked vs getuid()/getgid()) ->
//  ucred.label -> audit_token region (proc_ro + task_tokens + 0x8,
//  Dopamine proc_ucred_update_content recipe, credits docs/CREDITS.md).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P095UcredLadder : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
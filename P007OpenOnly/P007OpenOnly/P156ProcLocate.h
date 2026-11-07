//
//  P156ProcLocate.h
//  P007OpenOnly
//
//  Symbol-free self-proc locator test for the post-KRW elevate chain.
//  mach_port_kobject(task_self) -> task_t, then (with a live lane) scan the
//  task struct for bsd_info (pid + proc_ro validate). No allproc/kernproc.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P156ProcLocate : NSObject
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END

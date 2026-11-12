//
//  LTDarkwordInterposer.c — exit() interposer for the vendored darksword
//  exploit. The verbatim kexploit's failure paths call sleep(2)+exit(c),
//  which kills the WHOLE app process "voluntarily" with no crash record
//  (receipt: 17 live syslog — pid 604/634, 7 s lifetime, no ReportCrash).
//  The interposer converts any exit(int) from the exploit into an ObjC
//  exception that LabProbeGuard catches inside the chain task: honest
//  receipt row, app keeps running. No vendored byte is modified.
//
//  dyld reads the interpose table automatically from __DATA,__interpose.
//

#import <Foundation/Foundation.h>
#import <stdio.h>

static void lt_interposed_exit(int code)
    __attribute__((noreturn));

static void lt_interposed_exit(int code) {
    // record the vendored-failure exit and unwind via exception
    fprintf(stderr, "[lt-interpose] exit(%d) intercepted -> raising\n", code);
    [NSException exceptionWithName:@"LTDarkswordExit"
                            reason:[NSString stringWithFormat:
                                @"vendored exploit called exit(%d)", code]
                          userInfo:@{@"exitCode": @(code)}];
    // never reached; exceptions need no return
    _exit(code);
}

static void (*lt_real_exit)(int) = NULL;

__attribute__((used, section("__DATA,__interpose")))
static struct { void *repl; void *orig; } lt_interpose_exit_entry[] = {
    { (void *)lt_interposed_exit, (void *)exit },
    { (void *)lt_interposed_exit, (void *)_exit },
};

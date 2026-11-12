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
#import <pthread.h>
#import <stdio.h>

static void lt_interposed_exit(int code)
    __attribute__((noreturn));

/* v2: pthread_exit instead of NSException. The exception unwind had to
   cross Swift async closure frames (undefined propagation) — receipts
   showed the app still exiting. pthread_exit kills ONLY the calling
   thread: the vendored exploit now runs on a DarkswordBridge worker, so
   a FAILURE-path exit() ends the worker; the app and chain live on, the
   bridge reports the failure as an honest miss row. */
static void lt_interposed_exit(int code) {
    fprintf(stderr, "[lt-interpose] exit(%d) intercepted -> pthread_exit\n", code);
    pthread_exit((void *)(uintptr_t)(code | 0x1000));
}

static void (*lt_real_exit)(int) = NULL;

__attribute__((used, section("__DATA,__interpose")))
static struct { void *repl; void *orig; } lt_interpose_exit_entry[] = {
    { (void *)lt_interposed_exit, (void *)exit },
    { (void *)lt_interposed_exit, (void *)_exit },
};

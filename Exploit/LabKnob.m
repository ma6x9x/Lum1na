//
//  LabKnob.m — generic per-test knob store. Lum1na / Lum1na-Debug.
//

#import "LabKnob.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <string.h>

/* legacy knobs that pre-date the generic store: the per-probe files the
   fires already read keep working, the generic UI writes the canonical
   form, and this alias list makes them one thing */
static NSString *LabKnobLegacyAlias(NSString *catalogId) {
    if ([catalogId isEqualToString:@"p143"]) return @"p143_resid.txt";
    if ([catalogId isEqualToString:@"p109"]) return @"p109_pid.txt";
    return nil;
}

static NSString *LabKnobDocsPath(void) {
    return [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

int LabKnobRead(const char *catalogId, char *out, int cap) {
    if (out && cap > 0) out[0] = '\0';
    if (!catalogId || !*catalogId || !out || cap <= 0) return 0;
    NSString *docs = LabKnobDocsPath();
    NSString *nm = [NSString stringWithUTF8String:catalogId];
    NSString *file = [docs stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"knob_%@.txt", nm]];
    NSString *txt = [NSString stringWithContentsOfFile:file
                            encoding:NSUTF8StringEncoding error:nil];
    if (txt.length == 0) {
        /* legacy fallback keeps the fires' own knob files authoritative */
        NSString *alias = LabKnobLegacyAlias(nm);
        if (alias) txt = [NSString stringWithContentsOfFile:
                          [docs stringByAppendingPathComponent:alias]
                          encoding:NSUTF8StringEncoding error:nil];
    }
    if (txt.length == 0) return 0;
    NSString *trim = [txt stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (trim.length == 0) return 0;
    strlcpy(out, trim.UTF8String ?: "", (size_t)cap);
    return 1;
}

int LabKnobWrite(const char *catalogId, const char *value) {
    if (!catalogId || !*catalogId || !value) return -1;
    NSString *docs = LabKnobDocsPath();
    NSString *nm = [NSString stringWithUTF8String:catalogId];
    NSString *file = [docs stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"knob_%@.txt", nm]];
    NSString *txt = [NSString stringWithUTF8String:value];
    if (![txt writeToFile:file atomically:YES encoding:NSUTF8StringEncoding
                    error:nil]) return -1;
    int fd = open(file.fileSystemRepresentation, O_RDONLY);
    if (fd >= 0) { (void)fcntl(fd, F_FULLFSYNC); (void)close(fd); }
    return 0;
}

#ifndef BRIDGING_HEADER_H
#define BRIDGING_HEADER_H

#import <Foundation/Foundation.h>
#import "KASLRLeak.h"
#import "UPLLeak.h"
#import "CSKRW.h"
#import "Momentarius.h"
#import "Persistence.h"

// Native Exploit/*.m (KASLRLeak, UPLLeak, ClearSword, Lum1naKRW) are excluded from
// the Lum1na app target via membershipExceptions. UI builds use Swift stubs in
// Exploit/Bridges/NativeLeakStubs.swift. Do not import IOKit-backed headers here.

#endif

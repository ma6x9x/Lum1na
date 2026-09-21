#ifndef Lum1na_Bridging_Header_h
#define Lum1na_Bridging_Header_h

#import <Foundation/Foundation.h>
#include <stdint.h>

// Base exploit primitives
#import "Exploit/KASLRLeak.h"
#import "Exploit/UPLLeak.h"
#import "Exploit/CSKRW.h"
#import "Exploit/ANE.h"

// Fusion Chain (REQUIRED - used by ExploitManager.swift)
#import "Exploit/Lum1naKRW.h"
#import "Exploit/FusionChain.h"
#import "Exploit/Bridges/FusionChainDelegate.h"

// CVE Controllers (optional - only if Swift needs direct access)
// These are used internally by FusionChain.m, so not strictly required here
// #import "Exploit/P009Controller.h"
// #import "Exploit/P052Controller.h"
// #import "Exploit/P039Controller.h"

// Bridges
#import "Exploit/Bridges/cs_run.h"

#endif

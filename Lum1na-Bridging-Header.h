#ifndef Lum1na_Bridging_Header_h
#define Lum1na_Bridging_Header_h

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// iOS-compatible Mach headers
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/vm_region.h>
#import <mach/message.h>
#import <mach/port.h>
#import <mach/task.h>

// iOS-compatible Mach-O
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

// System
#import <sys/mman.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <os/log.h>

// IOKit (iOS subset - NO IOBSD.h)
#import <IOKit/IOKitLib.h>

// CoreML
#import <CoreML/CoreML.h>

// VideoToolbox for P035
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>

// Your exploit headers - UPDATED
#import "Exploit/P044ExploitController.h"        // NEW: P044 ANE 254-input
#import "Exploit/AKSExploitController.h"          // AKS CVE-2026-65343
#import "Exploit/P051APFSXattr.h"                 // P051 APFS
#import "Exploit/P054APFSReapList.h"              // P054 APFS
#import "Exploit/LabRuntimeOffsets.h"
#import "Exploit/LabDeviceProfile.h"
#import "Exploit/A14_23F77_LabOffsets.h"
#import "Exploit/A12X_23G71_LabOffsets.h"

#endif

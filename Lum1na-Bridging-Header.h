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

// Your exploit headers
#import "Exploit/P044AksKaslrReach.h"
#import "Exploit/CVE_2026_65343_AKS.h"
#import "Exploit/P051APFSXattr.h"
#import "Exploit/P054APFSReapList.h"
#import "Exploit/LabRuntimeOffsets.h"
#import "Exploit/LabDeviceProfile.h"
#import "Exploit/A14_23F77_LabOffsets.h"
#import "Exploit/A12X_23G71_LabOffsets.h"

#endif

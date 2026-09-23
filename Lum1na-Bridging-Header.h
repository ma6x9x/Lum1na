//
//  Lum1na-Bridging-Header.h
//  iOS-only headers (no macOS-specific headers)
//

#ifndef Lum1na_Bridging_Header_h
#define Lum1na_Bridging_Header_h

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// MARK: - Mach Headers (iOS-compatible)
#import <mach/mach.h>
#import <mach/mach_types.h>
#import <mach/vm_map.h>
#import <mach/vm_region.h>
#import <mach/mach_traps.h>
#import <mach/mach_init.h>
#import <mach/thread_act.h>
#import <mach/task.h>
#import <mach/port.h>
#import <mach/message.h>
#import <mach/exception.h>
#import <mach/processor_info.h>
#import <mach/host_info.h>

// MARK: - Mach-O Headers
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>

// MARK: - System Headers
#import <sys/mman.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <pthread.h>
#import <os/log.h>

// MARK: - IOKit (iOS subset)
// NOTE: IOKit is limited on iOS - only user-space APIs available
#import <IOKit/IOKitLib.h>
// IOBSD.h does NOT exist on iOS - removed

// MARK: - CoreML (if needed)
#import <CoreML/CoreML.h>

// MARK: - Your Exploit Headers
// Only include headers that actually exist in your project
#import "Exploit/KASLRLeak.h"
#import "Exploit/P044AksKaslrReach.h"
#import "Exploit/CVE_2026_65343_AKS.h"
#import "Exploit/P051APFSXattr.h"
#import "Exploit/P054APFSReapList.h"
#import "Exploit/LabRuntimeOffsets.h"
#import "Exploit/LabDeviceProfile.h"
#import "Exploit/A14_23F77_LabOffsets.h"
#import "Exploit/A12X_23G71_LabOffsets.h"

#endif /* Lum1na_Bridging_Header_h */

//
//  Lum1na-Bridging-Header.h
//  iOS-compatible headers (no mach_vm.h)
//

#ifndef Lum1na_Bridging_Header_h
#define Lum1na_Bridging_Header_h

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// MARK: - Mach Headers (iOS-compatible)
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/vm_region.h>
#import <mach/mach_traps.h>
#import <mach/mach_init.h>
#import <mach/thread_act.h>
#import <mach/task.h>
#import <mach/port.h>
#import <mach/message.h>

// mach_vm.h is NOT available on iOS - use these instead:
// - vm_map.h for vm_map_64
// - mach.h for mach_port_t, kern_return_t, etc.

// MARK: - Mach-O Headers
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/getsect.h>

// MARK: - System Headers
#import <sys/mman.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <pthread.h>
#import <os/log.h>

// MARK: - IOKit
#import <IOKit/IOKitLib.h>
#import <IOKit/IOBSD.h>

// MARK: - CoreML (if needed)
#import <CoreML/CoreML.h>

// MARK: - Your Exploit Headers
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

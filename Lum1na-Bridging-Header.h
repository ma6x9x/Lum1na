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
#import "Exploit/P044ExploitController.h"
#import "Exploit/ANE254InputController.h"
#import "Exploit/AKSExploitController.h"
#import "Exploit/P051APFSXattr.h"
#import "Exploit/P054APFSReapList.h"
#import "Exploit/LabRuntimeOffsets.h"
#import "Exploit/LabDeviceProfile.h"
#import "Exploit/A14_23F77_LabOffsets.h"
#import "Exploit/A12X_23G71_LabOffsets.h"
#import "Exploit/DeviceIdentProbe.h"
#import "Exploit/LabIOGPUQueue.h"
#import "Exploit/P010QueueLeak.h"
#import "Exploit/P017ConfusedDeputy.h"
#import "Exploit/P032ANEOpenSmoke.h"
#import "Exploit/P033CoreML1in1out.h"
#import "Exploit/P034Kmsg3072Occupancy.h"
#import "Exploit/P040NamespaceDestSmoke.h"
#import "Exploit/P041SlideDestMap.h"
#import "Exploit/P042ReachabilityProbe.h"
#import "Exploit/P046F77PatchOracle.h"
#import "Exploit/P050GetattrlistOOB.h"
#import "Exploit/P053NECPDoubleFree.h"
#import "Exploit/P055IOSurfaceUPL.h"
#import "Exploit/P009ReplaceBackingSmoke.h"
#import "Exploit/P038WHuntSmoke.h"
#import "Exploit/P043WriteClassMap.h"
#import "Exploit/P045HybridMap.h"
#import "Exploit/P052APFSNstream.h"
#import "Exploit/CSKRW.h"
#import "Exploit/P005JIT.h"
#import "Exploit/Lockdownd/LockdowndFullChain.h"
#import "Exploit/CVE_2026_84530_KASLR.h"
#import "Exploit/P056VTCompressionReach.h"
#import "Kernel/Lum1naBoard.h"
#import "Kernel/Lum1naAfterKread.h"
#import "Exploit/CSRaceCalib.h"
#import "Exploit/APFS84523.h"
#import "Exploit/P057WVEKReach.h"
#import "Exploit/P058JPEGDriverReach.h"
#import "Exploit/P061AVEEncTypeReach.h"
#import "Exploit/Lum1naKRW.h"

#endif

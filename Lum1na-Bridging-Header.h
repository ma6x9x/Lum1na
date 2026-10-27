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
#import "Exploit/KRWBridge.h"
#import "Exploit/Lum1naCS2Core.h"
#import "Exploit/Lum1naCS2CoreController.h"
#import "Exploit/P044ExploitController.h"
#import "Exploit/ANE254InputController.h"
#import "Exploit/P027MetalCallback.h"
#import "Exploit/AKSExploitController.h"
#import "Exploit/P051APFSXattr.h"
#import "Exploit/P054APFSReapList.h"
#import "Exploit/LabRuntimeOffsets.h"
#import "Exploit/LabDeviceProfile.h"
#import "Exploit/A14_23F77_LabOffsets.h"
#import "Exploit/A12X_23G71_LabOffsets.h"
#import "Exploit/DeviceIdentProbe.h"
#import "Exploit/LabIOGPUQueue.h"
#import "Exploit/GPUStalePageProbe.h"
#import "BadQueryProbe.h"
#import "Exploit/P010QueueLeak.h"
#import "Exploit/P017ConfusedDeputy.h"
#import "Exploit/P032ANEOpenSmoke.h"
#import "Lum1naLogBridge.h"
#import "Exploit/P033CoreML1in1out.h"
#import "Exploit/P034Kmsg3072Occupancy.h"
#import "Exploit/P040NamespaceDestSmoke.h"
#import "Exploit/IOGPUStaleEntryProbe.h"
#import "Exploit/IOGPUReplaceRaceProbe.h"
#import "Exploit/P041SlideDestMap.h"
#import "Exploit/LightSword.h"
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
#import "Exploit/LightSwordCalib.h"
#import "Exploit/APFS84523.h"
#import "Exploit/P057WVEKReach.h"
#import "Exploit/P058JPEGDriverReach.h"
#import "Exploit/P061AVEEncTypeReach.h"
#import "Exploit/Lum1naSocketKRW.h"
#import "Exploit/ANEDirectIn.h"
#import "Exploit/P064AVE84607Racer.h"
#import "Exploit/P064Ht149041ChainMap.h"
#import "Exploit/P091DarkSwordChainMap.h"
#import "Exploit/P092Liter8PatchMap.h"
#import "Exploit/P093IntelCrossCheck.h"
#import "Exploit/P094KernprocDerive.h"
#import "Exploit/P095UcredLadder.h"
#import "Exploit/P097ConsoleSecLeak.h"
#import "Exploit/P098M2ScalerDiag.h"
#import "Exploit/P065FacetAOracle.h"
#import "Exploit/P066AveEncTypeMap.h"
#import "Exploit/P067AvdReach.h"
#import "Exploit/P068ChrootPrivMap.h"
#import "Exploit/P069DmaCommandMap.h"
#import "Exploit/P101DmaCommandFire.h"
#import "Exploit/P102TitanWriteTest.h"
#import "Exploit/P103M2ScalerCensus.h"
#import "Exploit/P106JPEGTeardownOracle.h"
#import "Exploit/P107AveWrapDims.h"
#import "Exploit/P104SepksCensus.h"
#import "Exploit/P105IosurfaceGates.h"
#import "Exploit/P108DiskImagesCensus.h"
#import "Exploit/P109AneSelSweep.h"
#import "Exploit/P112CGShading.h"
#import "Exploit/P113DescForgeControl.h"
#import "Exploit/P122SwordForge.h"
#import "Exploit/P123ShapeCensus.h"
#import "Exploit/P070ChainSequencer.h"
#import "Exploit/P071AneOverflowMap.h"
#import "Exploit/P072FileParserMap.h"
#import "Exploit/P073KCacheAnalyze.h"
#import "Exploit/P074KernelDump.h"
#import "Exploit/Lum1naKreadTest.h"
#import "Exploit/P06xLog.h"
#import "Exploit/ColdForge.h"
#import "Exploit/Rapier.h"
#import "Exploit/Anvil.h"
#import "Exploit/LightSwordABC.h"
#import "Exploit/DopamineCompat.h"
#import "Exploit/ANE254ChainController.h"
#import "Exploit/KRWChainController.h"
#import "Exploit/KRWTheoryChains.h"
#import "Exploit/DopaminePrimitives.h"
#import "Exploit/Lum1naLibkrw.h"


#endif

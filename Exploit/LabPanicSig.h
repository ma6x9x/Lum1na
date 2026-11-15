//
//  LabPanicSig.h — panic-PC ingest into the bandit ledger (the P123 anchor
//  law, automated). Mac side: tools/panic_pc.sh decodes a LOCAL .ips and
//  pushes ONE row (this device's own panic VA in hex) into
//  Documents/panic_pc.txt — the .ips itself never leaves the Mac. Device
//  side: LabPanicSigDrain() runs at tap begin; each row is scored against
//  this SKU's pinned unslid VAs (LabOffPins) and recorded:
//     hit  -> domain "panic", outcome "sig-panic-va" (+0.8), feats {pc, near}
//     miss -> outcome "panic-miss" (honest negative, feat near=none)
//  The file is truncated after the drain. Rows are THIS device's own VAs —
//  never cross-SKU pasted (T8101 != T8150 != T8027).
//

#ifndef LabPanicSig_h
#define LabPanicSig_h

/* Score any pushed rows in Documents/panic_pc.txt and clear them. */
void LabPanicSigDrain(void);

#endif /* LabPanicSig_h */

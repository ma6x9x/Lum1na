//
//  LabKnob.h — the generic per-test knob store (v3 individual-test-mode UI).
//
//  Every catalog id may carry one operator-supplied input value:
//      Documents/knob_<id>.txt        (canonical; UI writes here)
//      legacy aliases (read-fallback, e.g. p143 -> p143_resid.txt)
//  Probes read the value at tap time; the advisor prints it in the
//  advisory line; the SwiftUI knob editor writes it atomically. Probes
//  never lose their old default: a missing knob file = stock behavior.
//

#ifndef LabKnob_h
#define LabKnob_h

#import <stdint.h>

/* Read the knob for `catalogId` (canonical or legacy alias). Returns 1 and
   fills `out` (trimmed, NUL-safe) when a knob exists, 0 when not. */
int LabKnobRead(const char *catalogId, char *out, int cap);

/* Write/truncate the knob for `catalogId`. Atomic replace; F_FULLFSYNC. */
int LabKnobWrite(const char *catalogId, const char *value);

#endif /* LabKnob_h */

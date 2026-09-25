//
//  LabOffsets.swift
//  Lum1na
//
//  Swift helpers over the C LabOff() table. Do not duplicate VAs here —
//  Exploit/LabRuntimeOffsets.m is the runtime source of truth
//  (A14 23F77 / A12X 23G71 from P007 lab pins).
//

import Foundation

func labOffsetTag() -> String {
    guard let off = LabOff() else { return "unknown" }
    guard let cstr = off.pointee.tag else { return "unknown" }
    return String(cString: cstr)
}

func getCurrentDeviceTag() -> String {
    labOffsetTag()
}

func isA14() -> Bool {
    labOffsetTag().hasPrefix("A14")
}

func isA12X() -> Bool {
    labOffsetTag().hasPrefix("A12X")
}

//
//  ArmGateManager.swift — the ARMORY: in-app writer for arm-file gates.
//
//  2026-11-20. The panic-possible stages (LSIDCalib v12/v13, the lswkrw law,
//  p168 dangle, p169 malformed-type, p176 window loop) are gated by marker
//  files in Documents. Until now the only way to raise one was hand-creating
//  the file via the Files app — awkward enough that armed stages were rarely
//  raised correctly. The ARMORY writes/removes the markers in-app; they
//  persist across boots (Documents survives; app reinstall clears it).
//
//  Law preserved: presence-gated only, no content parsing — every reader in
//  the tree checks fileExistsAtPath. The marker body is provenance (WHO/WHEN
//  raised the gate), never configuration. Writes follow the PersistentLogStore
//  durability convention: POSIX open/write/F_FULLFSYNC.
//
//  Keep `gates` in sync when a probe adds a presence gate (grep _arm.txt).
//

import Foundation
import Darwin

enum ArmGate {
    struct Gate: Identifiable {
        let file: String
        let title: String
        let note: String
        var id: String { file }
    }

    /// Every presence gate in the tree (readers check existence only).
    static let gates: [Gate] = [
        .init(file: "cscalib_v12_arm.txt",
              title: "LSIDCalib v12 / v12.2",
              note: "stall class, fully bounded"),
        .init(file: "cscalib_v13_arm.txt",
              title: "LSIDCalib v13 purgeable",
              note: "CRASH class — solo tap, fresh boot"),
        .init(file: "lswkrw_arm.txt",
              title: "LightSword KRW (lswkrw law)",
              note: "presence gate, no content parsing"),
        .init(file: "p168_dangle_arm.txt",
              title: "P168 dangle (112477)",
              note: "PANIC-POSSIBLE — fresh boot, ONE tap"),
        .init(file: "p169_arm.txt",
              title: "P169 malformed type-id",
              note: "PANIC-POSSIBLE — fresh boot, ONE tap"),
        .init(file: "p176_arm.txt",
              title: "P176 window loop",
              note: "PANIC-POSSIBLE (reviewed 2026-11-18: parked)"),
    ]

    static var documents: String {
        NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first ?? ""
    }

    static func path(_ file: String) -> String {
        (documents as NSString).appendingPathComponent(file)
    }

    static func isSet(_ file: String) -> Bool {
        FileManager.default.fileExists(atPath: path(file))
    }

    private static func stamp() -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss z"
        return f.string(from: Date())
    }

    /// Raise (write marker + F_FULLFSYNC) or lower (unlink) a gate.
    /// Returns the resulting state (true = gate present).
    @discardableResult
    static func set(_ file: String, armed: Bool) -> Bool {
        let p = path(file)
        if armed {
            let body = "armed \(stamp()) — raised in-app (ARMORY)\n"
            let fd = open(p.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0o644)
            guard fd >= 0 else { return false }
            defer { close(fd) }
            let bytes = Array(body.utf8)
            let n = bytes.withUnsafeBufferPointer { ptr in
                write(fd, ptr.baseAddress, ptr.count)
            }
            if n != bytes.count { return false }
            fcntl(fd, F_FULLFSYNC)   // the PersistentLogStore durability law
        } else {
            unlink(p.fileSystemRepresentation)
        }
        return armed ? isSet(file) : !isSet(file)
    }
}

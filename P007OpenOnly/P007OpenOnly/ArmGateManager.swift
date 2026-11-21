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
        /// VALUE gate: when set, the marker body is this value (e.g. a path
        /// knob a probe reads as content) instead of a provenance stamp.
        /// Presence law unchanged — readers that only check existence are
        /// unaffected; readers that parse content get the intended value.
        var value: String? = nil
        var id: String { file }
    }

    /// Every presence gate in the tree (readers check existence only).
    /// VALUE gates carry the content their reader parses.
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
        .init(file: "p116_rw_path.txt",
              title: "P116 rw probe (WRITE escape)",
              note: "VALUE gate — arms the p116 read-write test with the safe /var/mobile target; the next p116 tap tests the WRITE class",
              value: "/var/mobile/Library/p116_rw_probe.txt"),
        .init(file: "p073_victim.txt",
              title: "P073 victim class = INPCB",
              note: "VALUE gate (v7h dial) — switches the p073 hole band to LIVE UDP sockets: a smashed inpcb is adopted directly by SocketKRW (the ANE lane's conversion door)",
              value: "inpcb"),
        .init(file: "p132_land.txt",
              title: "P132 landing stage",
              note: "presence gate — arms the p073 landing stage inside the P132 chain frame"),
        .init(file: "t8_race_arm.txt",
              title: "T8 aio->NECP race stage",
              note: "presence gate — arms the T8 (krw8) aio close-race + the same-CPU NECP battery (the 192-class reclaim). PANIC-POSSIBLE at the teardown's second put — fresh boot, ONE tap. Unarmed = the PANIC-FREE dry lane"),
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
        let pNS = p as NSString    /* fileSystemRepresentation is NSString-side on the 16.4 SDK */
        if armed {
            /* VALUE gates carry the content their reader parses (the p116 rw
               target path); everything else gets the provenance stamp. */
            let body: String
            if let v = Self.gates.first(where: { $0.file == file })?.value {
                body = v + "\n"
            } else {
                body = "armed \(stamp()) — raised in-app (ARMORY)\n"
            }
            let fd = open(pNS.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0o644)
            guard fd >= 0 else { return false }
            defer { close(fd) }
            let bytes = Array(body.utf8)
            let n = bytes.withUnsafeBufferPointer { ptr in
                write(fd, ptr.baseAddress, ptr.count)
            }
            if n != bytes.count { return false }
            fcntl(fd, F_FULLFSYNC)   // the PersistentLogStore durability law
        } else {
            unlink(pNS.fileSystemRepresentation)
        }
        return armed ? isSet(file) : !isSet(file)
    }
}

import Foundation

enum SessionPhase: Equatable {
    case check, unsupported, hold, armed, running, done, failed
}

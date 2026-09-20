import Foundation

struct Lum1naTests {
    static func smokeTest() -> Bool {
        !Compatibility.supportedDevelopmentTargets.isEmpty
    }
}

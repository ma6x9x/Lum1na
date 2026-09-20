import Foundation

struct DeviceProfile {
    let identifier: String
    let systemVersion: OperatingSystemVersion
}

protocol DeviceCapabilities {
    func currentProfile() -> DeviceProfile
}

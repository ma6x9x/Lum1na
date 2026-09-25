import Foundation

/// Local wall clock, 24-hour (military). Matches `LabLocalMilitaryNow()`
/// in `Exploit/LabLocalTime.m` (`yyyy-MM-dd HH:mm:ss z`, POSIX locale, local TZ).
enum LabTime {
    private static let formatter: DateFormatter = {
        let fmt = DateFormatter()
        fmt.locale = Locale(identifier: "en_US_POSIX")
        fmt.timeZone = TimeZone.current
        fmt.dateFormat = "yyyy-MM-dd HH:mm:ss z"
        return fmt
    }()

    static func militaryNow(from date: Date = Date()) -> String {
        formatter.string(from: date)
    }

    static func sysctl(_ name: String) -> String {
        var size = 0
        sysctlbyname(name, nil, &size, nil, 0)
        guard size > 0 else { return "?" }
        var buf = [CChar](repeating: 0, count: size)
        sysctlbyname(name, &buf, &size, nil, 0)
        return String(cString: buf)
    }

    static func unameRelease() -> String {
        var u = utsname()
        uname(&u)
        return withUnsafePointer(to: &u.release) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) {
                String(cString: $0)
            }
        }
    }
}

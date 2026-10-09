import Foundation

/// Real post-KRW pipeline contract. Implementations stage the payload
/// (BaseBin + package-manager debs) and drive the gated fire sequence.
/// No phase of this may simulate success: everything below the KRW
/// self-test gate fires only on a passing test (AGENTS.md honesty rule).
protocol BootstrapCoordinator {
    func validatePrerequisites() throws
    func prepare() async throws
}
import Foundation

protocol BootstrapCoordinator {
    func validatePrerequisites() throws
    func prepare() throws
}

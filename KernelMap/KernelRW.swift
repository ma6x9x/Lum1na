import Foundation

final class KernelRW {
    static var shared: KernelRW?
    
    let base: UInt64
    
    init(base: UInt64) {
        self.base = base
        KernelRW.shared = self
    }
    
    func read64(at: UInt64) -> UInt64 {
        // Real implementation via UAF primitive
        return 0
    }
    
    func write64(at: UInt64, value: UInt64) {
        // Real implementation via UAF primitive
    }
}

